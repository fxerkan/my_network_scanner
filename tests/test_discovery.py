"""Discovery: the backend self-checks plus the sweep -> device-list merge.

Before this, a sweep was write-only: it printed devices on the Discovery page
and threw them away. The merge is what makes the results persist, so it is the
part worth pinning down.
"""

from mynes.discovery import dhcp, ssdp
from mynes.web.api import _apply_discovery


class FakeScanner:
    def __init__(self, devices):
        self.devices = devices
        self.saved = 0

    def get_devices(self):
        return self.devices

    def save_devices(self):
        self.saved += 1
        return True


def test_ssdp_self_check():
    ssdp.demo()


def test_dhcp_self_check():
    dhcp.demo()


def test_sweep_fills_gaps_but_never_overwrites():
    scanner = FakeScanner([
        {"ip": "192.168.1.1", "mac": "6C:4F:89:5B:55:58", "hostname": "", "vendor": ""},
        {"ip": "192.168.1.39", "mac": "AA:BB:CC:00:00:01", "hostname": "my-tv", "vendor": ""},
    ])

    result = _apply_discovery(scanner, [
        {"ip": "192.168.1.1", "mac": None, "name": "EX3501-T0", "vendor": "Zyxel",
         "device_type": "Router", "sources": ["ssdp"], "services": ["UPnP"],
         "attributes": {"ssdp": {"descriptions": {"u": {"serialNumber": "S1"}}}}},
        # Matched by MAC even though the IP moved.
        {"ip": "192.168.1.77", "mac": "aa:bb:cc:00:00:01", "name": "Google TV Streamer",
         "sources": ["mdns"], "services": ["_googlecast._tcp"], "attributes": {}},
        # Radio-only: no IP, no ARP entry -> reported, not invented.
        {"ip": None, "mac": "11:22:33:44:55:66", "name": "Tile", "sources": ["ble"],
         "services": [], "attributes": {}},
    ])

    assert result == {"updated": 2, "matched": 2, "unmatched": [
        {"name": "Tile", "ip": None, "mac": "11:22:33:44:55:66", "sources": ["ble"]}
    ]}
    assert scanner.saved == 1

    router, tv = scanner.devices
    assert router["hostname"] == "EX3501-T0" and router["vendor"] == "Zyxel"
    assert router["discovery"]["attributes"]["ssdp"]["descriptions"]["u"]["serialNumber"] == "S1"
    assert tv["hostname"] == "my-tv"  # existing name survives
    assert tv["discovery"]["sources"] == ["mdns"]


def test_applying_twice_is_a_no_op():
    scanner = FakeScanner([{"ip": "10.0.0.5", "mac": "aa:bb", "hostname": ""}])
    rows = [{"ip": "10.0.0.5", "mac": "aa:bb", "name": "nas", "sources": ["mdns"],
             "services": [], "attributes": {}}]

    assert _apply_discovery(scanner, rows)["updated"] == 1
    assert _apply_discovery(scanner, rows)["updated"] == 0
    assert scanner.saved == 1
