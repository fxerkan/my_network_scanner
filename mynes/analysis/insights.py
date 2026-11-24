"""Network Insights - the passive half.

What a host on a switched LAN can honestly say about where devices go:

* **Internet egress** from this host: gateway reachability, the routed path
  to the internet (first public hop = the ISP edge), the public IP.
* **DNS**: which resolvers DHCP hands out, how fast they answer, whether
  they filter (an ad/tracker domain answered with 0.0.0.0 / NXDOMAIN means a
  filtering resolver such as AdGuard DNS sits in the path).
* **What each device announces** (mDNS/SSDP/Tuya/... broadcasts, recorded by
  the passive listener in discovery/dhcp.py), including SSDP SERVER headers
  that name an OS and firmware.
* **Where each device is expected to talk** - a curated table of vendor
  cloud, telemetry and firmware endpoints, matched on identity/vendor. These
  are labelled *expected*, never *observed*: per-device DNS needs a resolver
  that sees client IPs (docs/plans/adguard-home-rpifx.md), and the
  ``dns_source`` field says so instead of pretending.

Pure functions (``classify_filtering``, ``expected_endpoints``,
``device_summary``) are tested in ``demo()``; the probes below do I/O and
never raise.
"""

from __future__ import annotations

import os
import re
import socket
import struct
import time

# ---------------------------------------------------------------------------
# Raw DNS (stdlib only)
# ---------------------------------------------------------------------------


def _dns_query(name: str, qtype: int = 1) -> tuple[bytes, int]:
    qid = int.from_bytes(os.urandom(2), "big")
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.strip(".").split(".")) + b"\x00"
    return struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", qtype, 1), qid


def _parse_a_answers(buf: bytes) -> tuple[int, list[str]]:
    """Pure: (rcode, [IPv4 answers]) from a DNS response."""
    from mynes.core.diagnostics import _dns_read_name
    if len(buf) < 12:
        return -1, []
    flags, qd, an = struct.unpack(">H", buf[2:4])[0], *struct.unpack(">HH", buf[4:8])
    rcode = flags & 0x0F
    off, ips = 12, []
    try:
        for _ in range(qd):
            _, off = _dns_read_name(buf, off)
            off += 4
        for _ in range(an):
            _, off = _dns_read_name(buf, off)
            rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", buf[off:off + 10])
            off += 10
            if rtype == 1 and rdlen == 4:
                ips.append(socket.inet_ntoa(buf[off:off + 4]))
            off += rdlen
    except (ValueError, struct.error, IndexError):
        pass
    return rcode, ips


def resolve_via(server: str, name: str, timeout: float = 2.0) -> dict:
    """A query to one resolver. -> {ok, rcode, ips, ms, error}."""
    pkt, qid = _dns_query(name)
    started = time.monotonic()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(pkt, (server, 53))
            while True:
                raw, _ = s.recvfrom(4096)
                if int.from_bytes(raw[:2], "big") == qid:
                    break
    except OSError as e:
        return {"ok": False, "error": str(e), "ms": None, "ips": [], "rcode": None}
    rcode, ips = _parse_a_answers(raw)
    return {"ok": rcode == 0, "rcode": rcode, "ips": ips, "ms": round((time.monotonic() - started) * 1000, 1)}


# Domains every ad/tracker blocklist carries. A resolver that answers them
# with a sinkhole is filtering.
FILTER_TEST_DOMAINS = ("doubleclick.net", "googleadservices.com", "app-measurement.com")
SINKHOLE = {"0.0.0.0", "127.0.0.1", "94.140.14.33", "94.140.14.35"}


def classify_filtering(results: list[dict]) -> str:
    """Pure: test-domain answers -> 'filtering' | 'not filtering' | 'unknown'."""
    seen = [r for r in results if r.get("rcode") is not None]
    if not seen:
        return "unknown"
    blocked = sum(1 for r in seen if r["rcode"] == 3 or (r.get("ips") and set(r["ips"]) <= SINKHOLE)
                  or (r["rcode"] == 0 and not r.get("ips")))
    return "filtering" if blocked >= max(1, len(seen) // 2 + 1) else "not filtering"


# ---------------------------------------------------------------------------
# Expected endpoints - curated, labelled as knowledge, not observation
# ---------------------------------------------------------------------------
# purpose: control (app/cloud control), telemetry (analytics, usage, ACR),
# firmware (updates), media (streams/content), time (NTP).

VENDOR_ENDPOINTS = [
    (r"tuya|s-link|ai-link", [
        ("*.tuyaeu.com / a1.tuyaeu.com", "control", "Tuya cloud MQTT/HTTPS - device control and state"),
        ("*.tuyaeu.com (log)", "telemetry", "device event/usage logs to Tuya"),
        ("*.tuya.com (OTA)", "firmware", "OTA firmware")]),
    (r"petkit", [
        ("api.petkt.com / api.eu-pet.com", "control", "Petkit cloud API"),
        ("*.iot.petkit / MQTT", "control", "real-time state over MQTT"),
        ("*.aliyuncs.com", "media", "photos/video storage (Aliyun OSS)")]),
    (r"roborock", [
        ("*.roborock.com / mqtt-eu.roborock.com", "control", "Roborock cloud + MQTT"),
        ("*.roborock.com (logs)", "telemetry", "cleaning records, map uploads"),
        ("ota.roborock.com", "firmware", "OTA")]),
    (r"tp-?link|tapo|deco", [
        ("*.tplinkcloud.com / n-devs.tplinkcloud.com", "control", "TP-Link cloud"),
        ("*.tplinknbu.com", "telemetry", "usage statistics"),
        ("download.tplinkcloud.com", "firmware", "OTA")]),
    (r"philips|mxchip", [
        ("*.philips-connect / *.versuni.com", "control", "Philips Air+ cloud"),
        ("*.aliyuncs.com / *.amazonaws.com", "control", "MQTT broker for the Air+ app")]),
    (r"dyson", [
        ("*.cp.dyson.com", "control", "Dyson Link cloud"),
        ("*.iot.eu-west-1.amazonaws.com", "telemetry", "AWS IoT: sensor history uploads")]),
    (r"samsung", [
        ("*.samsungcloudsolution.com / *.samsungotn.net", "control", "SmartThings / TV services"),
        ("*.samsungacr.com", "telemetry", "ACR - automatic content recognition (what is on screen)"),
        ("*.samsungads.com / config.samsungads.com", "telemetry", "TV advertising / viewing data"),
        ("*.samsungotn.net (OTA)", "firmware", "firmware updates")]),
    (r"google|android|pixel|chromecast", [
        ("*.googleapis.com / *.gvt1.com", "control", "Google services / updates"),
        ("app-measurement.com / firebaselogging", "telemetry", "Firebase/Google analytics"),
        ("*.googlevideo.com", "media", "YouTube streams")]),
    (r"apple|macbook|ipad|iphone", [
        ("*.icloud.com / *.apple.com", "control", "iCloud and Apple services"),
        ("*.metrics.icloud.com / xp.apple.com", "telemetry", "Apple diagnostics/analytics"),
        ("mesu.apple.com", "firmware", "software updates")]),
    (r"anker|solix|fantasia", [
        ("*.anker.com / ankerpower-api", "control", "Anker cloud API + MQTT"),
        ("*.amazonaws.com", "telemetry", "power history uploads")]),
    (r"fujitsu|airstage|azurewave", [
        ("*.airstagelight.com / airstage cloud", "control", "AirStage cloud (optional - HA uses the local API)")]),
    (r"espressif", [
        ("vendor cloud (unknown)", "control", "ESP32 module - endpoints depend on the product")]),
    (r"zyxel", [
        ("*.zyxel.com / ACS (TR-069)", "control", "ISP remote management (TR-069)"),
        ("*.zyxel.com", "firmware", "firmware")]),
    (r"raspberry", [
        ("archive.raspberrypi.com / deb.debian.org", "firmware", "OS updates"),
        ("pool.ntp.org", "time", "NTP")]),
]
_ENDPOINT_RX = [(re.compile(rx, re.I), rows) for rx, rows in VENDOR_ENDPOINTS]


def expected_endpoints(device: dict) -> list[dict]:
    """Pure: curated vendor endpoints for one device, by vendor/identity/name."""
    ident = device.get("identity") or {}
    ha = device.get("home_assistant") or {}
    text = " ".join(str(x or "") for x in (device.get("vendor"), ident.get("vendor"), device.get("alias"),
                                            device.get("model"), ha.get("manufacturer"),
                                            " ".join(ha.get("integrations") or [])))
    out, seen = [], set()
    for rx, rows in _ENDPOINT_RX:
        if rx.search(text):
            for domain, purpose, note in rows:
                if domain not in seen:
                    seen.add(domain)
                    out.append({"domain": domain, "purpose": purpose, "note": note, "source": "expected"})
    return out


def device_summary(device: dict, chatter: dict | None = None) -> dict:
    """Pure: one row of the Insights device table."""
    mac = (device.get("mac") or "").lower()
    talks = (chatter or {}).get(mac) or {}
    endpoints = expected_endpoints(device)
    purposes = sorted({e["purpose"] for e in endpoints})
    ident = device.get("identity") or {}
    return {
        "key": device.get("ip") or device.get("mac"),
        "ip": device.get("ip"), "mac": device.get("mac"),
        "name": device.get("alias") or device.get("hostname") or device.get("ip") or device.get("mac"),
        "type": device.get("device_type"), "vendor": device.get("vendor"),
        "status": device.get("status"),
        "broadcasts": {p: {"count": v.get("count", 0), "last": v.get("last"), "server": v.get("server")}
                       for p, v in talks.items()},
        "expected_endpoints": endpoints,
        "telemetry_expected": "telemetry" in purposes,
        "cloud_dependent": "control" in purposes,
        "identity_reasons": ident.get("reasons") or [],
    }


# ---------------------------------------------------------------------------
# Probes (I/O, never raise)
# ---------------------------------------------------------------------------


def public_ip(timeout: float = 2.0) -> str | None:
    """myip.opendns.com asked of resolver1.opendns.com: a DNS-only echo, no HTTP."""
    r = resolve_via("208.67.222.222", "myip.opendns.com", timeout=timeout)
    return (r.get("ips") or [None])[0]


def internet_report(gateway: str | None, dhcp_server: dict | None = None) -> dict:
    from mynes.core import diagnostics

    report = {"gateway": gateway, "dhcp": dhcp_server or {}, "at": time.strftime("%Y-%m-%dT%H:%M:%S")}
    if gateway:
        report["gateway_ping"] = diagnostics.ping(gateway, count=3, timeout=1.0)
    trace = diagnostics.traceroute("1.1.1.1", max_hops=12, timeout=1.0)
    hops = trace.get("hops") or []
    for h in hops:
        ip = h.get("ip")
        h["private"] = bool(ip) and bool(re.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)", ip))
    report["path"] = {"target": "1.1.1.1", "hops": hops, "reached": trace.get("reached_target"),
                      "isp_edge": next((h["ip"] for h in hops if h.get("ip") and not h["private"]), None)}
    report["internet_up"] = bool(trace.get("reached_target")) or any(h.get("ip") and not h["private"] for h in hops)

    servers = [s for s in ((dhcp_server or {}).get("name_server") or []) if isinstance(s, str)]
    if gateway and gateway not in servers:
        servers = servers or [gateway]
    dns = []
    for srv in servers[:3]:
        probe = resolve_via(srv, "example.com")
        tests = [resolve_via(srv, d) for d in FILTER_TEST_DOMAINS]
        dns.append({"server": srv, "lookup": probe, "filtering": classify_filtering(tests),
                    "tests": [{"domain": d, **t} for d, t in zip(FILTER_TEST_DOMAINS, tests)]})
    report["dns"] = dns
    report["public_ip"] = public_ip()
    report["dns_source"] = {
        "per_device": False,
        "detail": "Per-device DNS needs a resolver that sees client IPs (AdGuard Home on this host). "
                  "The LAN currently forwards to the router, so only expected endpoints are shown.",
        "plan": "docs/plans/adguard-home-rpifx.md",
    }
    return report


def demo():
    q, qid = _dns_query("example.com")
    assert q[12:] == b"\x07example\x03com\x00\x00\x01\x00\x01"
    ans = (struct.pack(">HHHHHH", qid, 0x8180, 1, 1, 0, 0) + q[12:]
           + b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton("93.184.216.34"))
    assert _parse_a_answers(ans) == (0, ["93.184.216.34"])
    assert classify_filtering([{"rcode": 0, "ips": ["0.0.0.0"]}, {"rcode": 3, "ips": []},
                               {"rcode": 0, "ips": ["142.250.1.1"]}]) == "filtering"
    assert classify_filtering([{"rcode": 0, "ips": ["142.250.1.1"]}] * 3) == "not filtering"
    assert classify_filtering([{"rcode": None}]) == "unknown"
    ep = expected_endpoints({"vendor": "Samsung Electronics", "device_type": "Smart TV"})
    assert any(e["purpose"] == "telemetry" and "acr" in e["domain"] for e in ep)
    row = device_summary({"ip": "192.168.1.78", "mac": "B4:C9:B9:69:7F:A6", "vendor": "Tuya",
                          "alias": "S-Link feeder"},
                         {"b4:c9:b9:69:7f:a6": {"Tuya": {"count": 12, "last": "x"}}})
    assert row["broadcasts"]["Tuya"]["count"] == 12 and row["cloud_dependent"] and row["telemetry_expected"]
    assert expected_endpoints({"vendor": "Unknown"}) == []
    print("insights: OK")
    return True


if __name__ == "__main__":
    demo()
