"""Discovery: the backend self-checks plus the sweep -> device-list merge.

Before this, a sweep was write-only: it printed devices on the Discovery page
and threw them away. The merge is what makes the results persist, so it is the
part worth pinning down.
"""

import pytest

from mynes.discovery import bluetooth, dhcp, ssdp
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


# --- BLE availability ------------------------------------------------------
#
# The container image ships bleak, so `import bleak` succeeding no longer means
# BLE can work: on Linux it also needs the host's D-Bus system bus mounted in.
# Without this check the backend reported "ok" and returned zero devices, which
# reads exactly like a scan that found nothing.

@pytest.fixture
def _no_dbus_env(monkeypatch):
    monkeypatch.delenv("DBUS_SYSTEM_BUS_ADDRESS", raising=False)
    monkeypatch.setattr(bluetooth.sys, "platform", "linux")


def test_ble_unavailable_without_a_system_bus(monkeypatch, _no_dbus_env):
    monkeypatch.setattr(bluetooth, "_is_socket", lambda _p: False)
    monkeypatch.setattr(bluetooth.BluetoothBackend, "requires", ())

    ok, reason = bluetooth.BluetoothBackend().available()
    assert ok is False
    assert "/run/dbus/system_bus_socket" in reason


def test_ble_available_when_the_bus_is_mounted(monkeypatch, _no_dbus_env):
    monkeypatch.setattr(bluetooth, "_is_socket",
                        lambda p: p == bluetooth.DBUS_SYSTEM_SOCKET)
    monkeypatch.setattr(bluetooth.BluetoothBackend, "requires", ())

    assert bluetooth.BluetoothBackend().available() == (True, "ok")


def test_a_directory_is_not_a_bus(tmp_path, monkeypatch, _no_dbus_env):
    """docker creates a *directory* when a bind mount's source is missing.

    os.path.exists is true for it, so the old shape of this check would have
    called a typo'd mount healthy and failed later with "No such file".
    """
    monkeypatch.setattr(bluetooth, "DBUS_SYSTEM_SOCKET", str(tmp_path))
    monkeypatch.setattr(bluetooth.BluetoothBackend, "requires", ())

    assert bluetooth.BluetoothBackend().available()[0] is False


def test_dbus_address_env_overrides_the_default_path(tmp_path, monkeypatch):
    monkeypatch.setattr(bluetooth.sys, "platform", "linux")
    monkeypatch.setenv("DBUS_SYSTEM_BUS_ADDRESS",
                       f"unix:path={tmp_path / 'bus'},guid=abc")
    monkeypatch.setattr(bluetooth, "_is_socket",
                        lambda p: p == str(tmp_path / "bus"))
    monkeypatch.setattr(bluetooth.BluetoothBackend, "requires", ())

    assert bluetooth.BluetoothBackend().available() == (True, "ok")


def test_non_unix_dbus_address_is_taken_on_faith(monkeypatch):
    """A tcp: bus cannot be stat'd - refusing to scan would be a false negative."""
    monkeypatch.setattr(bluetooth.sys, "platform", "linux")
    monkeypatch.setenv("DBUS_SYSTEM_BUS_ADDRESS", "tcp:host=10.0.0.2,port=1234")
    monkeypatch.setattr(bluetooth, "_is_socket", lambda _p: False)
    monkeypatch.setattr(bluetooth.BluetoothBackend, "requires", ())

    assert bluetooth.BluetoothBackend().available() == (True, "ok")


def test_non_linux_never_looks_for_a_socket(monkeypatch):
    """macOS goes through CoreBluetooth; there is no bus to find."""
    monkeypatch.setattr(bluetooth.sys, "platform", "darwin")
    monkeypatch.setattr(bluetooth, "_is_socket", lambda _p: False)
    monkeypatch.setattr(bluetooth.BluetoothBackend, "requires", ())

    assert bluetooth.BluetoothBackend().available() == (True, "ok")


def test_missing_bleak_still_wins_over_the_bus_check(monkeypatch):
    """A clear "install bleak" must not be masked by a D-Bus complaint."""
    monkeypatch.setattr(bluetooth.sys, "platform", "linux")
    monkeypatch.setattr(bluetooth.BluetoothBackend, "requires", ("not_a_real_module",))

    ok, reason = bluetooth.BluetoothBackend().available()
    assert ok is False
    assert "not_a_real_module" in reason


def test_applying_twice_is_a_no_op():
    scanner = FakeScanner([{"ip": "10.0.0.5", "mac": "aa:bb", "hostname": ""}])
    rows = [{"ip": "10.0.0.5", "mac": "aa:bb", "name": "nas", "sources": ["mdns"],
             "services": [], "attributes": {}}]

    assert _apply_discovery(scanner, rows)["updated"] == 1
    assert _apply_discovery(scanner, rows)["updated"] == 0
    assert scanner.saved == 1
