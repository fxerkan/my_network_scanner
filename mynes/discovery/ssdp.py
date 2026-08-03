"""SSDP / UPnP discovery - stdlib sockets only, no dependency.

Catches what mDNS misses: routers, smart TVs, DLNA renderers, IP cameras,
game consoles and most Windows-flavoured gear.

The M-SEARCH reply is only a pointer: its LOCATION header points at the
device's description XML, which is where the real identity lives (friendly
name, manufacturer, model, serial). That is what Home Assistant shows in its
SSDP discovery panel, so we fetch and parse it too.
"""

from __future__ import annotations

import logging
import re
import socket
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
from xml.etree import ElementTree

log = logging.getLogger(__name__)

from mynes.discovery.base import DiscoveredDevice, DiscoveryBackend

MCAST = ("239.255.255.250", 1900)

M_SEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: {mx}\r\n"
    "ST: {st}\r\n"
    "\r\n"
)

# Broad first, then targets that some devices only answer specifically.
SEARCH_TARGETS = [
    "ssdp:all",
    "upnp:rootdevice",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    "urn:schemas-upnp-org:device:MediaRenderer:1",
    "urn:schemas-upnp-org:device:MediaServer:1",
    "urn:dial-multiscreen-org:service:dial:1",
    "urn:schemas-sony-com:service:ScalarWebAPI:1",
]

DEVICE_TYPE_HINTS = [
    (r"InternetGatewayDevice|WANDevice|wfa-igd", "Router"),
    (r"MediaRenderer|dial-multiscreen|Roku|Samsung.*TV|WebOS", "Smart TV"),
    (r"MediaServer|MiniDLNA|Plex|Jellyfin|Emby", "Media Server"),
    (r"Printer|printer", "Printer"),
    (r"NAS|Synology|QNAP", "NAS"),
    (r"basic:1|Philips hue|Hue Bridge", "Smart Home"),
    (r"Xbox|PlayStation", "Gaming Console"),
    (r"IPCamera|NetworkCamera|Camera", "IP Camera"),
]

_HEADER = re.compile(r"^([A-Za-z0-9_.-]+)\s*:\s*(.*)$")


def _parse(payload: str) -> dict[str, str]:
    headers = {}
    for line in payload.splitlines()[1:]:
        m = _HEADER.match(line.strip())
        if m:
            headers[m.group(1).upper()] = m.group(2).strip()
    return headers


# Fields worth lifting out of a UPnP device description document.
DESC_FIELDS = (
    "friendlyName", "manufacturer", "manufacturerURL", "modelName",
    "modelNumber", "modelDescription", "modelURL", "serialNumber",
    "UDN", "presentationURL", "deviceType",
)


def parse_description(xml_text: str) -> dict:
    """UPnP description XML -> flat dict.

    Namespaces differ per vendor, so tags are matched on the local name.
    Document order puts the root device first, so first-wins keeps the root's
    identity rather than an embedded sub-device's.
    """
    root = ElementTree.fromstring(xml_text)
    out: dict = {}
    for el in root.iter():
        tag = el.tag.rsplit("}", 1)[-1]
        text = (el.text or "").strip()
        if not text:
            continue
        if tag in DESC_FIELDS:
            out.setdefault(tag, text)
        elif tag == "serviceType":
            out.setdefault("serviceTypes", [])
            if text not in out["serviceTypes"]:
                out["serviceTypes"].append(text)
    return out


def fetch_description(url: str, timeout: float = 3.0) -> dict:
    """GET the description document. Returns {} on any failure - a device that
    advertises a URL it will not serve is common, not an error."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 - checked by caller
            return parse_description(resp.read(262144).decode("utf-8", "replace"))
    except Exception as e:  # noqa: BLE001 - LAN gear serves malformed XML routinely
        log.debug("ssdp: description fetch failed for %s: %s", url, e)
        return {}


def _fetchable(url: str, ip: str) -> bool:
    """Only fetch the device's *own* advertised URL over http(s).

    Without this a device on the LAN could point LOCATION at any host and make
    the scanner issue requests on its behalf.
    """
    u = urlparse(url)
    return u.scheme in ("http", "https") and u.hostname == ip


def _guess_type(blob: str) -> str | None:
    for pattern, dtype in DEVICE_TYPE_HINTS:
        if re.search(pattern, blob, re.I):
            return dtype
    return None


class SSDPBackend(DiscoveryBackend):
    name = "ssdp"
    requires = ()

    def discover(self, timeout: float = 5.0) -> list[DiscoveredDevice]:
        mx = max(1, min(int(timeout) - 1, 5))
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(timeout)

        devices: dict[str, DiscoveredDevice] = {}
        try:
            for st in SEARCH_TARGETS:
                try:
                    sock.sendto(M_SEARCH.format(mx=mx, st=st).encode(), MCAST)
                except OSError:
                    continue

            import time

            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                sock.settimeout(max(0.2, deadline - time.monotonic()))
                try:
                    data, addr = sock.recvfrom(65507)
                except (TimeoutError, socket.timeout):
                    break
                except OSError:
                    break

                headers = _parse(data.decode("utf-8", "replace"))
                ip = addr[0]
                dev = devices.get(f"ip:{ip}")
                if dev is None:
                    dev = DiscoveredDevice(source="ssdp", ip=ip, services=["UPnP"])
                    devices[f"ip:{ip}"] = dev

                server = headers.get("SERVER", "")
                st_val = headers.get("ST") or headers.get("NT") or ""
                location = headers.get("LOCATION", "")
                usn = headers.get("USN", "")

                blob = " ".join([server, st_val, usn, location])
                dev.device_type = dev.device_type or _guess_type(blob)
                dev.name = dev.name or headers.get("FRIENDLYNAME.DLNA.ORG") or None
                dev.model = dev.model or headers.get("X-MODELNAME") or headers.get("MODELNAME")

                attrs = dev.attributes.setdefault("ssdp", {})
                attrs.setdefault("search_targets", [])
                if st_val and st_val not in attrs["search_targets"]:
                    attrs["search_targets"].append(st_val)
                if server:
                    attrs["server"] = server
                if location:
                    attrs.setdefault("locations", [])
                    if location not in attrs["locations"]:
                        attrs["locations"].append(location)
                    attrs["location"] = attrs["locations"][0]
                    attrs["description_port"] = urlparse(location).port
                if usn:
                    attrs["usn"] = usn
        finally:
            sock.close()

        self._enrich_from_descriptions(list(devices.values()))
        return list(devices.values())

    @staticmethod
    def _enrich_from_descriptions(devices: list[DiscoveredDevice], timeout: float = 3.0) -> None:
        """Fetch every advertised description.xml and fold it into the device."""
        jobs = [
            (dev, url)
            for dev in devices
            for url in dev.attributes.get("ssdp", {}).get("locations", [])
            if dev.ip and _fetchable(url, dev.ip)
        ]
        if not jobs:
            return

        with ThreadPoolExecutor(max_workers=min(len(jobs), 16)) as pool:
            docs = list(pool.map(lambda j: fetch_description(j[1], timeout), jobs))

        for (dev, url), doc in zip(jobs, docs):
            if not doc:
                continue
            descriptions = dev.attributes.setdefault("ssdp", {}).setdefault("descriptions", {})
            descriptions[url] = doc

            dev.name = dev.name or doc.get("friendlyName")
            dev.vendor = dev.vendor or doc.get("manufacturer")
            dev.model = dev.model or doc.get("modelName") or doc.get("modelNumber")
            dev.device_type = dev.device_type or _guess_type(
                " ".join([doc.get("deviceType", ""), doc.get("modelName", ""),
                          doc.get("modelDescription", ""), doc.get("manufacturer", "")])
            )
            for svc in doc.get("serviceTypes", []):
                short = svc.split(":")[-2] if svc.count(":") >= 2 else svc
                if short not in dev.services:
                    dev.services.append(short)


def discover(timeout: float = 5.0) -> list[DiscoveredDevice]:
    return SSDPBackend().safe_discover(timeout=timeout)


def demo() -> None:
    doc = parse_description(
        '<?xml version="1.0"?>'
        '<root xmlns="urn:schemas-upnp-org:device-1-0"><device>'
        "<deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>"
        "<friendlyName>EX3501-T0</friendlyName><manufacturer>Zyxel</manufacturer>"
        "<modelName>EX3501-T0</modelName><serialNumber>S1234</serialNumber>"
        "<serviceList><service><serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1"
        "</serviceType></service></serviceList>"
        "<deviceList><device><friendlyName>WANDevice</friendlyName></device></deviceList>"
        "</device></root>"
    )
    assert doc["friendlyName"] == "EX3501-T0", doc  # root wins over the embedded device
    assert doc["manufacturer"] == "Zyxel"
    assert doc["serialNumber"] == "S1234"
    assert doc["serviceTypes"] == ["urn:schemas-upnp-org:service:Layer3Forwarding:1"]

    assert parse_description("<root/>") == {}

    # A device may only be asked for its own URL, over http(s).
    assert _fetchable("http://192.168.1.1:8080/desc.xml", "192.168.1.1")
    assert not _fetchable("http://10.0.0.9/desc.xml", "192.168.1.1")
    assert not _fetchable("file:///etc/passwd", "192.168.1.1")

    dev = DiscoveredDevice(source="ssdp", ip="192.168.1.1")
    dev.attributes["ssdp"] = {"locations": ["http://192.168.1.1/nope.xml"]}
    SSDPBackend._enrich_from_descriptions([dev], timeout=0.2)  # unreachable -> no crash
    print("ssdp demo ok")


if __name__ == "__main__":
    demo()
    for d in discover(6.0):
        desc = next(iter((d.attributes.get("ssdp", {}).get("descriptions") or {}).values()), {})
        print(f"{d.ip:<16} {d.name or '?':<24} {desc.get('manufacturer', ''):<16} {desc.get('modelName', '')}")
