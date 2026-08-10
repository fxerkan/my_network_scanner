"""Enhanced-analysis results must survive the scan that rebuilds self.devices.

Regression: run_enhanced_analysis grabbed a device reference, ran nmap for
minutes, and a scan replaced self.devices in the meantime - so the write landed
on an orphan and never reached disk (device showed no "Details" button).
apply_enhanced_analysis re-locates the LIVE device instead of trusting a stale
reference.
"""
import threading
import types

from mynes.core.scanner import LANScanner


def _stub(devices):
    saved = {"count": 0}
    s = types.SimpleNamespace(
        devices=devices,
        _io_lock=threading.RLock(),
    )
    def save():
        saved["count"] += 1
    s.save_to_json = save
    return s, saved


def test_enhanced_write_hits_the_live_device_not_a_stale_ref():
    # A scan has just rebuilt the list; the object the caller held is gone.
    live = [{"ip": "192.168.1.62", "mac": "d8:3a:dd:de:d8:67", "status": "online"}]
    s, saved = _stub(live)

    LANScanner.apply_enhanced_analysis(
        s, "192.168.1.62", "d8:3a:dd:de:d8:67",
        {"web_services": {"http_80": {"title": "Pi"}}},
        discovered_ports=[{"port": 8443, "service": "https"}],
    )

    dev = live[0]
    assert dev["enhanced_comprehensive_info"], "enhanced info must be written"
    assert dev["last_enhanced_analysis"]
    assert dev["analysis_data"]["enhanced_analysis_info"]
    assert any(p.get("port") == 8443 for p in dev["open_ports"])
    assert saved["count"] == 1, "must persist exactly once"


def test_relocates_by_mac_when_ip_flapped():
    # The adapter (MAC) is stable but its IP flapped since analysis started.
    live = [{"ip": "192.168.1.116", "mac": "d8:3a:dd:de:d8:67", "status": "online"}]
    s, _ = _stub(live)

    LANScanner.apply_enhanced_analysis(
        s, "192.168.1.62", "d8:3a:dd:de:d8:67", {"os": "linux"}
    )
    assert live[0]["enhanced_comprehensive_info"] == {"os": "linux"}


def test_creates_stub_when_device_vanished():
    live = []
    s, _ = _stub(live)
    LANScanner.apply_enhanced_analysis(s, "10.0.0.9", "aa:bb:cc:dd:ee:ff", {"x": 1})
    assert len(live) == 1 and live[0]["enhanced_comprehensive_info"] == {"x": 1}


if __name__ == "__main__":
    test_enhanced_write_hits_the_live_device_not_a_stale_ref()
    test_relocates_by_mac_when_ip_flapped()
    test_creates_stub_when_device_vanished()
    print("enhanced persistence: OK")
