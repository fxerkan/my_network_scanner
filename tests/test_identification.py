"""Device identification: the self-checks plus the merge rule they depend on.

Every assert here corresponds to something this scanner actually got wrong on
a real home LAN, so they are regression tests rather than illustrations.
"""

from mynes.analysis import fingerprint
from mynes.core import models, topology
from mynes.discovery import onvif


def test_fingerprint_self_check():
    fingerprint.demo()


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
