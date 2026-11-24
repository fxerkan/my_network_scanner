"""Scan results and user edits must survive scheduled scans and DHCP moves.

Two bugs found on a real install, where the inventory froze for three months:
- the monitoring scheduler scanned but never saved, and every page load
  reloaded the stale file over the fresh in-memory scan;
- a device that DHCP moved to a new IP lost every user-set field, because
  the stored record was keyed mac@old_ip.
"""

from mynes.core.diagnostics import demo as diagnostics_demo
from mynes.core.scanner import LANScanner
from mynes.monitoring.scheduler import MonitorScheduler


def test_moved_device_keeps_its_record():
    existing = {
        "aa:bb:cc:00:00:01@192.168.1.10": {
            "ip": "192.168.1.10", "mac": "aa:bb:cc:00:00:01", "alias": "Mutfak",
            "location": "Kitchen", "user_modified": {"alias": "Mutfak", "location": "Kitchen"},
        },
    }
    arp = [{"ip": "192.168.1.32", "mac": "aa:bb:cc:00:00:01"}]
    moves = LANScanner._rekey_moved_devices(existing, arp)
    assert moves == [("aa:bb:cc:00:00:01", "192.168.1.10", "192.168.1.32")]
    moved = existing["aa:bb:cc:00:00:01@192.168.1.32"]
    assert moved["alias"] == "Mutfak" and moved["location"] == "Kitchen"
    assert moved["previous_ips"] == ["192.168.1.10"]
    assert "aa:bb:cc:00:00:01@192.168.1.10" not in existing


def test_ambiguous_or_docker_macs_are_not_moved():
    existing = {
        "02:42:ac:11:00:02@172.17.0.2": {"ip": "172.17.0.2", "mac": "02:42:ac:11:00:02"},
        "aa:bb:cc:00:00:02@192.168.1.20": {"ip": "192.168.1.20", "mac": "aa:bb:cc:00:00:02"},
    }
    arp = [
        {"ip": "172.18.0.2", "mac": "02:42:ac:11:00:02"},      # docker reuse
        {"ip": "192.168.1.21", "mac": "aa:bb:cc:00:00:02"},    # dual-homed:
        {"ip": "192.168.1.22", "mac": "aa:bb:cc:00:00:02"},    # two IPs now
    ]
    assert LANScanner._rekey_moved_devices(existing, arp) == []
    assert set(existing) == {"02:42:ac:11:00:02@172.17.0.2", "aa:bb:cc:00:00:02@192.168.1.20"}


def test_scheduled_scan_persists(monkeypatch):
    saved = []

    class FakeScanner:
        devices = []

        def scan_network(self, include_offline=False):
            self.devices = [{"ip": "192.168.1.5", "mac": "aa:bb:cc:dd:ee:05", "status": "online"}]

        def save_to_json(self):
            saved.append(list(self.devices))
            return True

        def get_devices(self):
            return self.devices

    sched = MonitorScheduler(FakeScanner())
    settings = dict(sched.settings(), run_discovery=False, notify=False)
    monkeypatch.setattr("mynes.monitoring.store.load_state", lambda: {})
    monkeypatch.setattr("mynes.monitoring.store.save_state", lambda s: s)
    monkeypatch.setattr("mynes.monitoring.store.add_alerts", lambda a: None)
    try:
        sched.run_once(settings)
    except Exception:
        pass  # anything after the save (notify, HA push) is out of scope here
    assert saved and saved[0][0]["ip"] == "192.168.1.5"


def test_diagnostics_selfcheck():
    assert diagnostics_demo()


def test_int_ports_do_not_break_migration():
    from mynes.core.models import UnifiedDeviceModel
    d = UnifiedDeviceModel().migrate_legacy_data(
        {"ip": "172.18.0.2", "mac": "12:17:8b:35:b8:43", "open_ports": [8680, 8680, 80]})
    assert [p["port"] for p in d["open_ports"]][:1] == [8680]
