"""Home Assistant comparison logic. No network: every input is a literal."""

import pytest

from mynes.integrations.home_assistant import (
    _identifiers_in_name,
    _name_keys,
    _protocol_for,
    demo,
)


def test_payload_self_check():
    demo()


@pytest.mark.parametrize(
    "name,expected",
    [
        ("192_168_1_79", ("192.168.1.79", None)),          # HA `generic` integration
        ("192.168.1.79", ("192.168.1.79", None)),
        ("hci0 (D8:3A:DD:DE:D8:69)", (None, "d8:3a:dd:de:d8:69")),
        ("Kamera C200", (None, None)),
        ("999_168_1_79", (None, None)),                     # octet out of range
        (None, (None, None)),
    ],
)
def test_identifiers_are_mined_from_names(name, expected):
    """HA device names are often the only identifier those entries carry."""
    assert _identifiers_in_name(name) == expected


def test_name_keys_collapse_across_both_sides():
    assert _name_keys({"hostname": "rpifx.local"}) == _name_keys({"name": "RPiFX"})
    assert _name_keys({"name": "rpi-fx"}) == {"rpifx"}


def test_short_names_are_not_matched():
    """'tv' or 'pi' would match half a home network."""
    assert _name_keys({"name": "tv"}) == set()
    assert _name_keys({"name": "pi"}) == set()


def test_protocol_classification():
    assert _protocol_for(["zha"]) == "Zigbee"
    assert _protocol_for(["matter"]) == "Matter"
    assert _protocol_for(["tuya"]) == "Cloud"
    assert _protocol_for(["samsungtv"]) == "IP"
    # HACS repos and helpers are registry entries but not devices.
    assert _protocol_for(["hacs"]) == "Not a device"
    assert _protocol_for(["sun"]) == "Not a device"
    assert _protocol_for([]) == "unknown"


def test_match_count_cannot_exceed_device_count():
    """Regression: unioning a MAC set with an IP set double-counted devices and
    reported 37 matches against 31 devices."""
    from mynes.integrations.home_assistant import HomeAssistantClient

    client = HomeAssistantClient(url="http://x", token="t")
    ha = [{"mac": "aa:bb:cc:dd:ee:ff", "ip": "10.0.0.5", "name": "Pi", "protocol": "IP"}]
    mine = [{"mac": "AA:BB:CC:DD:EE:FF", "ip": "10.0.0.5", "hostname": "pi.local"}]

    client.device_registry = lambda: ha
    result = client.compare(mine)

    assert result["in_both"] == 1, "one device matching on mac AND ip is still one device"
    assert result["in_both"] <= result["mynes_total"]
    assert result["only_in_mynes"] == []
    assert result["only_in_home_assistant"] == []


def test_non_devices_are_excluded_from_the_diff():
    from mynes.integrations.home_assistant import HomeAssistantClient

    client = HomeAssistantClient(url="http://x", token="t")
    client.device_registry = lambda: [
        {"name": "HACS repo", "protocol": "Not a device"},
        {"name": "Living room lamp", "protocol": "Zigbee"},
    ]
    result = client.compare([])
    assert result["home_assistant_total"] == 1
    assert result["home_assistant_excluded"] == 1


def test_credentials_from_env(monkeypatch):
    """Home Assistant credentials come from the canonical HA_URL / HA_TOKEN."""
    from mynes.integrations.home_assistant import HomeAssistantClient

    for var in ("HA_URL", "HA_TOKEN"):
        monkeypatch.delenv(var, raising=False)

    assert not HomeAssistantClient().configured()

    monkeypatch.setenv("HA_URL", "http://ha:8123/")
    monkeypatch.setenv("HA_TOKEN", "the-token")
    client = HomeAssistantClient()
    assert client.configured()
    assert client.url == "http://ha:8123"        # trailing slash trimmed
    assert client.token == "the-token"


def test_dotenv_never_overrides_a_real_environment_variable(tmp_path, monkeypatch):
    from mynes import load_dotenv

    env = tmp_path / ".env"
    env.write_text('HA_URL=http://from-file\nexport HA_TOKEN="quoted"\n# comment\n\n')
    monkeypatch.setenv("HA_URL", "http://from-shell")
    monkeypatch.delenv("HA_TOKEN", raising=False)

    applied = load_dotenv(env)
    assert applied == ["HA_TOKEN"], applied
    import os

    assert os.environ["HA_URL"] == "http://from-shell"
    assert os.environ["HA_TOKEN"] == "quoted"
