from mynes.analysis.identity import demo as identity_demo
from mynes.analysis.probes import demo as probes_demo
from mynes.discovery.dhcp import demo as dhcp_demo


def test_identity():
    assert identity_demo()


def test_probes():
    assert probes_demo()


def test_dhcp():
    dhcp_demo()
