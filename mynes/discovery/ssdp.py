"""SSDP / UPnP discovery - stdlib sockets only, no dependency.

Catches what mDNS misses: routers, smart TVs, DLNA renderers, IP cameras,
game consoles and most Windows-flavoured gear.
"""

from __future__ import annotations

import re
import socket
from urllib.parse import urlparse

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
                    attrs["location"] = location
                    attrs["description_port"] = urlparse(location).port
                if usn:
                    attrs["usn"] = usn
        finally:
            sock.close()

        return list(devices.values())


def discover(timeout: float = 5.0) -> list[DiscoveredDevice]:
    return SSDPBackend().safe_discover(timeout=timeout)


if __name__ == "__main__":
    for d in discover(6.0):
        print(f"{d.ip:<16} {d.device_type or '?':<16} {d.attributes.get('ssdp', {}).get('server', '')}")
