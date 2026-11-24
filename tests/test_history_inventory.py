"""The History cross-filter's slim inventory rows."""

import json

from mynes.web.api import history_rows


def test_history_rows_shape_and_coercion():
    rows = history_rows([
        {"ip": "192.168.1.5", "mac": "AA:BB:CC:00:00:05", "alias": "TV", "vendor": "Samsung",
         "device_type": "Smart TV", "status": "online", "location": "Living Room",
         "last_seen": "2026-11-24T10:00:00", "analysis_data": {"huge": "blob"}},
        {"ip": "", "mac": "a4:c1:38:65:e0:9a", "hostname": None, "vendor": None,
         "device_type": None, "status": "offline"},
        "not a device",
    ])
    assert len(rows) == 2
    tv, ble = rows
    assert tv["key"] == "192.168.1.5" and tv["mac"] == "aa:bb:cc:00:00:05"
    assert tv["name"] == "TV" and tv["status"] == "online"
    assert "analysis_data" not in tv
    # No-IP device: keyed by MAC, Unknown fills the blanks.
    assert ble["key"] == "a4:c1:38:65:e0:9a" and ble["name"] == "a4:c1:38:65:e0:9a"
    assert ble["vendor"] == "Unknown" and ble["device_type"] == "Unknown"
    # Every value is a plain string, so sorted-key JSON can never trip on it.
    json.dumps(rows, sort_keys=True)
    assert all(isinstance(v, str) for r in rows for v in r.values())
