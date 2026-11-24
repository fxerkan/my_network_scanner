"""HA inventory + selective import, and imported devices surviving scans."""

from mynes.core.models import UnifiedDeviceModel
from mynes.integrations.home_assistant import demo as ha_demo, import_devices


def test_home_assistant_demo():
    ha_demo()


def test_imported_radio_device_survives_scan_migration():
    mine = []
    import_devices(mine, [{"id": "zb1", "name": "Kapı Sensörü", "manufacturer": "SONOFF", "model": "SNZB-04",
                           "integrations": ["zha"], "protocol": "Zigbee", "area": "Hol", "status": "active"}])
    dev = mine[0]
    assert dev["mac"] == "ha:zb1" and dev["ip"] == ""
    # scan_network rebuilds every stored record through migrate_legacy_data;
    # the import's provenance, location and HA block must come through intact.
    migrated = UnifiedDeviceModel().migrate_legacy_data(dev)
    for field in ("home_assistant", "location", "discovery_only", "source", "model"):
        assert migrated.get(field) == dev.get(field), field
    assert migrated["alias"] == "Kapı Sensörü" and migrated["status"] == "online"


def test_location_and_identity_survive_migration():
    dev = {"ip": "192.168.1.32", "mac": "68:79:c4:f9:2d:ed", "alias": "Philips", "location": "Kitchen",
           "trust_status": "trusted", "identity": {"device_type": "Air Purifier", "confidence": 0.97}}
    migrated = UnifiedDeviceModel().migrate_legacy_data(dev)
    assert migrated["location"] == "Kitchen" and migrated["trust_status"] == "trusted"
    assert migrated["identity"]["confidence"] == 0.97
