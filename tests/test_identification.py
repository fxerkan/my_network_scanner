"""Device identification: the self-checks plus the merge rule they depend on.

Every assert here corresponds to something this scanner actually got wrong on
a real home LAN, so they are regression tests rather than illustrations.
"""

from mynes.analysis import fingerprint, os_detect
from mynes.core import diagnostics, models, subnets, topology
from mynes.discovery import onvif


def test_fingerprint_self_check():
    fingerprint.demo()


def test_os_detect_self_check():
    os_detect.demo()


def test_subnets_self_check():
    subnets.demo()


def test_diagnostics_self_check():
    diagnostics.demo()


def test_onvif_self_check():
    onvif.demo()


def test_topology_self_check():
    topology.demo()


def test_camera_ports_are_actually_scanned():
    """554 was missing from the fast scan, so no RTSP camera was ever found."""
    for port in (554, 8554, 10554, 2020):
        assert port in fingerprint.SCAN_PORTS


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
