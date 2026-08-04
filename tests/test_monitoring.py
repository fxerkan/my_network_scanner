"""The alerting logic runs the self-checks that ship with each module.

Keeping the asserts in `demo()` means they also run from `python -m mynes.x`
while debugging; pytest just calls the same function.
"""

from mynes.integrations import home_assistant
from mynes.monitoring import notify, push, rules, uptime


def test_rules_self_check():
    rules.demo()


def test_notify_self_check():
    notify.demo()


def test_push_self_check():
    push.demo()


def test_uptime_self_check():
    uptime.demo()


def test_home_assistant_self_check():
    home_assistant.demo()


def test_offline_alert_is_not_repeated_every_scan():
    """A device that stays down must alert once, not on every single scan."""
    prev = {"aa": {"mac": "aa", "ip": "10.0.0.2", "status": "online"}}
    gone: dict = {}

    fired, misses = rules.evaluate(prev, gone)
    assert fired == []  # first miss is tolerated

    fired, misses = rules.evaluate(prev, gone, miss_counts=misses)
    assert [a.rule for a in fired] == [rules.DEVICE_OFFLINE]

    for _ in range(5):
        fired, misses = rules.evaluate(prev, gone, miss_counts=misses)
        assert fired == [], "must stay quiet while the device remains offline"


def test_disabled_rules_are_filtered_out():
    prev: dict = {}
    cur = {"aa": {"mac": "aa", "ip": "10.0.0.2", "status": "online"}}
    fired, _ = rules.evaluate(prev, cur, enabled_rules=[rules.DEVICE_OFFLINE])
    assert fired == []


def test_first_run_records_a_baseline_instead_of_alerting():
    """Regression: with no previous snapshot every device looked new, so the
    first scheduled scan reported the whole network as arrivals (49 alerts)."""
    current = {
        f"aa:bb:cc:00:00:{i:02x}": {"mac": f"aa:bb:cc:00:00:{i:02x}", "ip": f"10.0.0.{i}", "status": "online"}
        for i in range(30)
    }
    alerts, _ = rules.evaluate({}, current)
    assert alerts == [], f"first run must be silent, got {len(alerts)}"

    # ...but a genuine arrival on the NEXT run still alerts.
    later = {**current, "aa:bb:cc:99:99:99": {"mac": "aa:bb:cc:99:99:99", "ip": "10.0.0.99", "status": "online"}}
    alerts, _ = rules.evaluate(current, later)
    assert [a.rule for a in alerts] == [rules.NEW_DEVICE]


def test_rotating_ble_addresses_do_not_alert():
    """macOS hands out a fresh CoreBluetooth UUID per session; treating those as
    devices means 'new device' on every single scan."""
    known = {"aa:bb:cc:00:00:01": {"mac": "aa:bb:cc:00:00:01", "ip": "10.0.0.1", "status": "online"}}
    with_ble = {
        **known,
        "7de7f807-a905-9e49-54fd-7cad1f3e786d": {
            "mac": "7DE7F807-A905-9E49-54FD-7CAD1F3E786D", "status": "online",
        },
    }
    alerts, _ = rules.evaluate(known, with_ble)
    assert alerts == [], [a.title for a in alerts]


def test_stable_identity_detection():
    assert rules._has_stable_identity({"mac": "aa:bb:cc:dd:ee:ff"})
    assert rules._has_stable_identity({"ip": "10.0.0.5"})
    assert not rules._has_stable_identity({"mac": "7DE7F807-A905-9E49-54FD-7CAD1F3E786D"})
    assert not rules._has_stable_identity({})


def test_webhook_payload_carries_every_field_the_ha_guide_documents():
    """The setup guide tells users to write {{ trigger.json.X }} in their Home
    Assistant automation. If a field disappeared from the payload, those
    templates would silently render empty — so the docs are pinned here."""
    import json
    from unittest.mock import patch

    from mynes.monitoring import notify

    alert = rules.Alert(
        rule="device_offline", severity="warning",
        title="Device offline: rpifx",
        message="rpifx is unreachable.",
        device_name="rpifx", ip="192.168.1.116", mac="d8:3a:dd:de:d8:68",
    ).to_dict()

    captured = {}

    def fake_post(url, data=None, headers=None, method="POST"):
        captured["url"] = url
        captured["body"] = json.loads(data if isinstance(data, str) else json.dumps(data))
        return 200, "ok"

    with patch.object(notify, "_post", fake_post):
        results = notify.dispatch(
            [{"type": "webhook", "url": "http://ha.local:8123/api/webhook/mynes-alert"}],
            [alert],
        )

    assert results and results[0]["ok"]
    assert captured["url"].endswith("/api/webhook/mynes-alert")
    for documented in ("title", "message", "severity", "rule", "ip", "device_name"):
        assert documented in captured["body"], f"the guide references trigger.json.{documented}"
    # Slack and Discord render a bare text/content field.
    assert captured["body"]["text"] and captured["body"]["content"]
