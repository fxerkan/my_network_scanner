"""ONVIF WS-Discovery - how IP cameras announce themselves.

An IP camera is the device an IP scan is worst at: often a single open port
(RTSP 554), no hostname, no mDNS, and an OUI registered to an anonymous
Shenzhen ODM. WS-Discovery is the one protocol they all speak, and its Probe
needs no credentials - the reply carries the camera's configured name, its
hardware model and the ONVIF service address (which is where the odd ports
like 2020 come from).

stdlib sockets and a regex. No onvif/zeep dependency, because we only read
two fields out of the SOAP envelope.
"""

from __future__ import annotations

import re
import socket
import time
import uuid

from mynes.discovery.base import DiscoveredDevice, DiscoveryBackend

MCAST = ("239.255.255.250", 3702)

# NetworkVideoTransmitter is the camera profile; Device catches NVRs, encoders
# and doorbells that do not advertise as a transmitter.
PROBE_TYPES = ("dn:NetworkVideoTransmitter", "tds:Device")

PROBE = """<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"
 xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing"
 xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
 xmlns:dn="http://www.onvif.org/ver10/network/wsdl"
 xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
 <e:Header>
  <w:MessageID>uuid:{mid}</w:MessageID>
  <w:To e:mustUnderstand="true">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>
  <w:Action e:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>
 </e:Header>
 <e:Body><d:Probe><d:Types>{types}</d:Types></d:Probe></e:Body>
</e:Envelope>"""

_XADDRS = re.compile(r"<[^>]*XAddrs[^>]*>(.*?)</[^>]*XAddrs>", re.I | re.S)
_SCOPES = re.compile(r"<[^>]*Scopes[^>]*>(.*?)</[^>]*Scopes>", re.I | re.S)
_HOST = re.compile(r"https?://([^/:]+)(?::(\d+))?")


def parse_scopes(scopes: str) -> dict[str, str]:
    """`onvif://www.onvif.org/name/Q3 .../hardware/IPC` -> {'name': 'Q3', ...}.

    Scope values are URL-quoted and may repeat; last one wins, which is what
    cameras expect.
    """
    from urllib.parse import unquote

    out: dict[str, str] = {}
    for scope in scopes.split():
        if not scope.startswith("onvif://"):
            continue
        path = scope.split("/", 3)[-1] if scope.count("/") >= 3 else ""
        key, _, value = path.partition("/")
        if key and value:
            out[key.lower()] = unquote(value).strip()
    return out


def parse_probe_match(payload: str, addr_ip: str) -> DiscoveredDevice | None:
    """One ProbeMatch envelope -> a DiscoveredDevice, or None if unusable."""
    xaddrs_match = _XADDRS.search(payload)
    xaddrs = (xaddrs_match.group(1).strip() if xaddrs_match else "").split()

    ip, onvif_port = addr_ip, None
    for url in xaddrs:
        host = _HOST.match(url)
        if host:
            ip = host.group(1) or addr_ip
            onvif_port = int(host.group(2)) if host.group(2) else 80
            break

    scopes_match = _SCOPES.search(payload)
    scopes = parse_scopes(scopes_match.group(1) if scopes_match else "")

    if not ip:
        return None

    return DiscoveredDevice(
        source="onvif",
        ip=ip,
        name=scopes.get("name") or None,
        model=scopes.get("hardware") or None,
        vendor=scopes.get("manufacturer") or None,
        device_type="IP Camera",
        services=["ONVIF", "RTSP"],
        attributes={
            "onvif": {
                "xaddrs": xaddrs,
                "port": onvif_port,
                "scopes": scopes,
                "location": scopes.get("location", ""),
                "profile": scopes.get("profile", ""),
            }
        },
    )


class ONVIFBackend(DiscoveryBackend):
    name = "onvif"
    requires = ()

    def discover(self, timeout: float = 5.0) -> list[DiscoveredDevice]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

        devices: dict[str, DiscoveredDevice] = {}
        try:
            # Multicast over UDP loses replies. Two rounds of each probe cost
            # nothing and stop the camera list from changing between scans.
            for _ in range(2):
                for types in PROBE_TYPES:
                    message = PROBE.format(mid=uuid.uuid4(), types=types)
                    try:
                        sock.sendto(message.encode(), MCAST)
                    except OSError:
                        continue

            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                sock.settimeout(max(0.2, deadline - time.monotonic()))
                try:
                    data, addr = sock.recvfrom(65507)
                except (TimeoutError, socket.timeout):
                    break
                except OSError:
                    break

                dev = parse_probe_match(data.decode("utf-8", "replace"), addr[0])
                if dev is None:
                    continue
                existing = devices.get(dev.key())
                if existing is None:
                    devices[dev.key()] = dev
                else:
                    # A camera answers both probes; keep whichever named itself.
                    existing.name = existing.name or dev.name
                    existing.model = existing.model or dev.model
                    existing.vendor = existing.vendor or dev.vendor
        finally:
            sock.close()

        return list(devices.values())


def discover(timeout: float = 5.0) -> list[DiscoveredDevice]:
    return ONVIFBackend().safe_discover(timeout=timeout)


def demo():
    """Parses a real ProbeMatch captured from a Wansview camera."""
    sample = """<?xml version="1.0"?><SOAP-ENV:Envelope
    xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">
    <SOAP-ENV:Body><d:ProbeMatches><d:ProbeMatch>
    <d:Types>dn:NetworkVideoTransmitter</d:Types>
    <d:Scopes>onvif://www.onvif.org/type/video_encoder
    onvif://www.onvif.org/name/tkcx45cce9433ded20eaipcam000
    onvif://www.onvif.org/hardware/Q3
    onvif://www.onvif.org/location/city%2FIstanbul
    onvif://www.onvif.org/Profile/Streaming</d:Scopes>
    <d:XAddrs>http://192.168.1.78:2020/onvif/device_service</d:XAddrs>
    </d:ProbeMatch></d:ProbeMatches></SOAP-ENV:Body></SOAP-ENV:Envelope>"""

    dev = parse_probe_match(sample, "192.168.1.78")
    assert dev is not None
    assert dev.ip == "192.168.1.78", dev.ip
    assert dev.name == "tkcx45cce9433ded20eaipcam000", dev.name
    assert dev.model == "Q3", dev.model
    assert dev.device_type == "IP Camera"
    assert dev.attributes["onvif"]["port"] == 2020
    # URL-quoted scope values are decoded, so a location is readable.
    assert dev.attributes["onvif"]["location"] == "city/Istanbul"

    # A reply with no XAddrs still identifies the sender by its source address.
    bare = parse_probe_match("<d:ProbeMatch><d:Scopes></d:Scopes></d:ProbeMatch>",
                             "192.168.1.99")
    assert bare is not None and bare.ip == "192.168.1.99" and bare.name is None

    print("onvif: OK")
    return True


if __name__ == "__main__":
    import sys

    if "--live" in sys.argv:
        for d in discover(6.0):
            print(f"{d.ip:<16} {d.name or '?':<32} {d.model or ''}")
    else:
        demo()
