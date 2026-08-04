"""SSDP description-document handling. No network: XML and URLs are literals."""

import pytest

from mynes.discovery.ssdp import _fetchable, parse_description

NAMESPACED = """<root xmlns="urn:schemas-upnp-org:device-1-0">
  <device>
    <friendlyName>EX3501-T0</friendlyName>
    <manufacturer>ZYXEL</manufacturer>
    <modelName>EX3501-T0</modelName>
    <serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType></service></serviceList>
    <deviceList><device><friendlyName>Embedded sub-device</friendlyName></device></deviceList>
  </device>
</root>"""


def test_parses_through_vendor_namespaces():
    d = parse_description(NAMESPACED)
    assert d["friendlyName"] == "EX3501-T0"
    assert d["manufacturer"] == "ZYXEL"
    assert d["serviceTypes"] == ["urn:schemas-upnp-org:service:WANIPConnection:1"]


def test_root_device_wins_over_embedded_ones():
    """Document order puts the root first; a sub-device must not overwrite it."""
    assert parse_description(NAMESPACED)["friendlyName"] != "Embedded sub-device"


def test_malformed_xml_raises_for_the_caller_to_swallow():
    with pytest.raises(Exception):
        parse_description("<root><unclosed>")


@pytest.mark.parametrize(
    "url,ip,allowed",
    [
        ("http://192.168.1.1:8080/desc.xml", "192.168.1.1", True),
        ("https://192.168.1.1/desc.xml", "192.168.1.1", True),
        # A device must not be able to point LOCATION at someone else and make
        # the scanner fetch on its behalf.
        ("http://10.0.0.9/desc.xml", "192.168.1.1", False),
        ("http://evil.example/desc.xml", "192.168.1.1", False),
        ("file:///etc/passwd", "192.168.1.1", False),
        ("ftp://192.168.1.1/desc.xml", "192.168.1.1", False),
    ],
)
def test_only_the_devices_own_http_url_is_fetched(url, ip, allowed):
    assert _fetchable(url, ip) is allowed
