"""User edits must survive every scan.

The bug: editing a device (alias, hostname, vendor, device_type, notes, or any
hand-typed field) was silently overwritten by the next scan. The fix records
every edit in `user_modified` and reapplies it in merge_device_data, logging
what the scan wanted to change into `scan_log`.
"""

from mynes.core.models import UnifiedDeviceModel


def test_user_edits_win_over_scan():
    m = UnifiedDeviceModel()
    existing = {
        "ip": "192.168.1.32", "mac": "aa:bb:cc:dd:ee:ff",
        "hostname": "old-host", "vendor": "OldCorp",
        "device_type": "Camera", "alias": "Front Door Cam",
        "user_modified": {"alias": "Front Door Cam", "vendor": "OldCorp",
                          "device_type": "Camera"},
    }
    scan = {
        "ip": "192.168.1.32", "mac": "aa:bb:cc:dd:ee:ff",
        "hostname": "new-host", "vendor": "GenericVendor",
        "device_type": "Unknown", "alias": "unknown-device",
    }

    merged = m.merge_device_data(existing, scan, "normal_scan")

    # Every user-set field is preserved verbatim.
    assert merged["alias"] == "Front Door Cam"
    assert merged["vendor"] == "OldCorp"
    assert merged["device_type"] == "Camera"
    # hostname was NOT user-edited, so the scan value is allowed through.
    assert merged["hostname"] == "new-host"
    # The scan's differing guesses are logged, not lost.
    logged = {e["field"]: e["found"] for e in merged["scan_log"]}
    assert logged == {"vendor": "GenericVendor", "device_type": "Unknown",
                      "alias": "unknown-device"}


def test_migrate_restores_non_whitelisted_user_field():
    m = UnifiedDeviceModel()
    # `description` is not in the migrate whitelist, but the user typed it.
    legacy = {"ip": "192.168.1.50", "mac": "11:22:33:44:55:66",
              "description": "Kids' room tablet",
              "user_modified": {"description": "Kids' room tablet"}}
    unified = m.migrate_legacy_data(legacy)
    assert unified["description"] == "Kids' room tablet"
    assert unified["user_modified"]["description"] == "Kids' room tablet"


def test_update_device_null_mac_does_not_crash():
    """Editing a device whose update payload carries a null MAC (iPhones with a
    private/absent MAC send `mac: null` from the edit form) must not raise
    'NoneType' object has no attribute 'lower', and must not wipe the real MAC.
    """
    from mynes.core.scanner import LANScanner

    s = LANScanner.__new__(LANScanner)  # skip full init - update_device is self-contained
    s.devices = [{"ip": "192.168.1.90", "mac": "f6:43:1c:f3:9d:6a", "hostname": ""}]

    ok = s.update_device("192.168.1.90",
                         {"mac": None, "ip": "192.168.1.90",
                          "device_type": "Akıllı Telefon", "vendor": "Apple"})
    assert ok is True
    assert s.devices[0]["device_type"] == "Akıllı Telefon"
    assert s.devices[0]["vendor"] == "Apple"
    # A blank/None identity field in the payload must never erase the real one.
    assert s.devices[0]["mac"] == "f6:43:1c:f3:9d:6a"


if __name__ == "__main__":
    test_user_edits_win_over_scan()
    test_migrate_restores_non_whitelisted_user_field()
    test_update_device_null_mac_does_not_crash()
    print("ok")
