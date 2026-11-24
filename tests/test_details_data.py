"""The details panel renders what the record carries - so the record must keep it.

migrate_legacy_data used to drop every key it did not list (identity,
discovery_evidence, home_assistant, fingerprint, os_guess ...), and
merge_device_data took only four core fields from a fresh scan, so the scan's
own measurements never reached the store.
"""

from mynes.core.models import UnifiedDeviceModel


def test_migrate_keeps_unknown_keys():
    m = UnifiedDeviceModel()
    d = m.migrate_legacy_data({
        "ip": "192.168.1.63", "mac": "24:9e:7d:4f:07:df",
        "identity": {"device_type": "Vacuum Cleaner", "confidence": 0.9},
        "home_assistant": {"id": "x", "name": "Dock"},
        "discovery_evidence": {"dhcp_hostname": "roborock-dock"},
        "previous_ips": ["192.168.1.40"], "attributes": {"rssi": -60},
    })
    assert d["identity"]["confidence"] == 0.9
    assert d["home_assistant"]["name"] == "Dock"
    assert d["discovery_evidence"]["dhcp_hostname"] == "roborock-dock"
    assert d["previous_ips"] == ["192.168.1.40"] and d["attributes"]["rssi"] == -60


def test_merge_takes_fresh_scan_measurements():
    m = UnifiedDeviceModel()
    old = {"ip": "192.168.1.79", "mac": "30:68:93:8f:c5:36", "alias": "Cam",
           "fingerprint": {"reasons": ["old"]}, "identity": {"device_type": "IP Camera"}}
    new = {"ip": "192.168.1.79", "mac": "30:68:93:8f:c5:36",
           "fingerprint": {"reasons": ["RTSP on port 554"], "verdict": {"device_type": "IP Camera"}},
           "os_guess": {"os_family": "Linux"}, "connection_medium": {"medium": "wifi"},
           "stream_url": "rtsp://192.168.1.79:554/"}
    merged = m.merge_device_data(old, new, "normal_scan")
    assert merged["fingerprint"]["reasons"] == ["RTSP on port 554"]
    assert merged["os_guess"]["os_family"] == "Linux"
    assert merged["connection_medium"]["medium"] == "wifi"
    assert merged["stream_url"].startswith("rtsp://")
    assert merged["identity"]["device_type"] == "IP Camera"     # kept from the store
