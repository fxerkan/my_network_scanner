"""Device identification: the self-checks plus the merge rule they depend on.

Every assert here corresponds to something this scanner actually got wrong on
a real home LAN, so they are regression tests rather than illustrations.
"""

from mynes.analysis import fingerprint, os_detect
from mynes.core import diagnostics, models, subnets, topology
from mynes.discovery import onvif
from mynes.security import cve


def test_fingerprint_self_check():
    fingerprint.demo()


def test_os_detect_self_check():
    os_detect.demo()


def test_subnets_self_check():
    subnets.demo()


def test_diagnostics_self_check():
    diagnostics.demo()


def test_cve_self_check():
    cve.demo()


def test_onvif_self_check():
    onvif.demo()


def test_topology_self_check():
    topology.demo()


def test_camera_ports_are_actually_scanned():
    """554 was missing from the fast scan, so no RTSP camera was ever found."""
    for port in (554, 8554, 10554, 2020):
        assert port in fingerprint.SCAN_PORTS


def test_migration_keeps_user_device_type_marker():
    """The 'my Vacuum Cleaner keeps reverting' bug: migration dropped the
    device_type_source marker on load, so the next scan re-guessed the type."""
    legacy = {"ip": "192.168.1.60", "mac": "24:9e:7d:24:11:15",
              "device_type": "Vacuum Cleaner", "device_type_source": "user",
              "alias": "Living room robot", "alias_source": "user"}
    migrated = models.UnifiedDeviceModel().migrate_legacy_data(legacy)
    assert migrated["device_type"] == "Vacuum Cleaner"
    assert migrated["device_type_source"] == "user"
    assert migrated["alias_source"] == "user"

    # A retired guess-type stored by an older scan heals to the registered name.
    retired = models.UnifiedDeviceModel().migrate_legacy_data(
        {"ip": "1.2.3.4", "mac": "aa", "device_type": "Robot Vacuum"})
    assert retired["device_type"] == "Vacuum Cleaner"


def test_fingerprint_only_emits_registered_device_types():
    """A guessed type with no registry entry renders as a '?' icon + empty
    dropdown - exactly what happened to Roborock/Dyson/ESP devices."""
    from mynes.analysis import fingerprint
    from mynes.core.config import ConfigManager
    registered = set(ConfigManager().load_device_types())
    for _needle, dtype, _conf in fingerprint.VENDOR_TYPE_HINTS:
        assert dtype in registered, f"{dtype} is not a registered device type"


def test_generated_type_is_refreshed_but_a_user_choice_is_not():
    """One bad guess used to be permanent: the merge kept it forever."""
    device = {"mac": "aa:bb", "ip": "10.0.0.5"}
    guessed = {**device, "device_type": "Router", "device_type_source": "auto"}
    corrected = {**device, "device_type": "Raspberry Pi Server",
                 "device_type_source": "auto"}

    merged = models.UnifiedDeviceModel().merge_device_data(guessed, corrected)
    assert merged["device_type"] == "Raspberry Pi Server"

    chosen = {**device, "device_type": "Smart TV", "device_type_source": "user"}
    merged = models.UnifiedDeviceModel().merge_device_data(chosen, corrected)
    assert merged["device_type"] == "Smart TV"
    assert merged["device_type_source"] == "user"


def test_combined_rules_split_one_vendor_into_real_device_types():
    """Vendor alone calls a MacBook, an iPhone and an Apple TV the same thing."""
    from mynes.core.scanner import match_combined_rule

    rules = [
        {"vendor": r"Apple", "hostname": r"macbook", "type": "Laptop"},
        {"vendor": r"Apple", "hostname": r"iphone", "type": "Smartphone"},
        {"vendor": r"Apple", "hostname": r"[", "type": "Never"},   # broken regex
    ]
    assert match_combined_rule(rules, "apple, inc.", "fx-macbook-pro.local") == "Laptop"
    assert match_combined_rule(rules, "apple, inc.", "fx-iphone.local") == "Smartphone"
    # Vendor matches, hostname does not: no verdict, the heuristics get their turn.
    assert match_combined_rule(rules, "apple, inc.", "fx-ipad.local") is None
    # Hostname matches, vendor does not: a hostname called "macbook" on a TP-Link
    # NIC is not enough on its own - that is the whole point of the rule.
    assert match_combined_rule(rules, "tp-link", "macbook") is None
    assert match_combined_rule([], "apple", "macbook") is None


def test_vendor_pattern_conditions_are_literal_substrings_not_regex():
    """`conditions` gate a vendor rule so a chip-maker's OUI is not miscalled."""
    from mynes.core.scanner import match_vendor_pattern

    rules = [
        {"pattern": r"Samsung.*", "type": "Smartphone", "conditions": ["galaxy", "android"]},
        {"pattern": r"Zyxel.*", "type": "Router"},                       # bare fallback
        {"pattern": r"Dyson.*", "type": "Vacuum Cleaner", "conditions": ["vacuum", "robot"]},
        {"pattern": r"Dyson.*", "type": "Smart Home"},                   # ordering: after conditioned
        {"pattern": r"Bad(.*", "type": "Never"},                         # broken regex -> skipped
    ]
    # Condition met -> phone; condition absent (a Samsung Wi-Fi NIC) -> no verdict.
    assert match_vendor_pattern(rules, "samsung electronics", "galaxy-s24") == "Smartphone"
    assert match_vendor_pattern(rules, "samsung electronics", "fx-laptop") is None
    # Bare rule fires with no hostname signal at all.
    assert match_vendor_pattern(rules, "zyxel communications", "") == "Router"
    # First matching rule wins: the conditioned Dyson vacuum beats the generic one.
    assert match_vendor_pattern(rules, "dyson ltd", "robot-vacuum") == "Vacuum Cleaner"
    assert match_vendor_pattern(rules, "dyson ltd", "tp07-fan") == "Smart Home"


def test_shipped_defaults_classify_common_home_brands():
    """The expanded default rules cover the brands users actually own."""
    from mynes.core.scanner import match_combined_rule, match_vendor_pattern
    from mynes.core.config import ConfigManager

    dr = ConfigManager().default_config["detection_rules"]
    combined, vendor = dr["combined_rules"], dr["vendor_patterns"]

    assert match_combined_rule(combined, "xiaomi", "roborock-s7") == "Vacuum Cleaner"
    assert match_combined_rule(combined, "google", "living-room-chromecast") == "Streaming Device"
    assert match_vendor_pattern(vendor, "zyxel communications corp", "") == "Router"
    assert match_vendor_pattern(vendor, "tp-link technologies", "archer-ax55") == "Router"
    assert match_vendor_pattern(vendor, "signify netherlands", "hue-bridge") == "Smart Light"
    assert match_vendor_pattern(vendor, "synology inc", "") == "NAS"
    # Both are substring traps the ordering/token choices must survive:
    # "zenbook" must not hit the Asus router rule via a "zen" token...
    assert match_vendor_pattern(vendor, "asustek computer", "zenbook-laptop") == "Laptop"
    assert match_vendor_pattern(vendor, "asustek computer", "rt-ax88u-router") == "Router"
    # ...and "ambilight" (a TV feature) must not be read as a lamp via "light".
    assert match_vendor_pattern(vendor, "philips", "ambilight-tv") == "Smart TV"
    # Every type the shipped rules can emit must have an icon (no blank fallback).
    types = {r["type"] for r in combined} | {r["type"] for r in vendor}
    icons = ConfigManager().default_device_types
    assert not [t for t in types if t not in icons], "types missing an icon"
