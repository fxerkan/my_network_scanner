"""mDNS / DNS-SD (Bonjour, Avahi) discovery.

This is the single highest-value protocol for a home lab: printers, NAS boxes,
Chromecasts, HomeKit accessories, Home Assistant itself, Raspberry Pis and -
importantly - Matter devices all announce here. Matter commissioning uses
`_matterc._udp` and operational Matter nodes use `_matter._tcp`, so Matter
discovery comes free with mDNS rather than needing a separate stack.
"""

from __future__ import annotations

import socket

from mynes.discovery.base import DiscoveredDevice, DiscoveryBackend

# Service type -> (friendly label, device_type guess).
KNOWN_SERVICES = {
    "_matter._tcp.local.": ("Matter", "Smart Home"),
    "_matterc._udp.local.": ("Matter (commissionable)", "Smart Home"),
    "_matterd._udp.local.": ("Matter (commissioner)", "Smart Home"),
    "_hap._tcp.local.": ("HomeKit", "Smart Home"),
    "_home-assistant._tcp.local.": ("Home Assistant", "Server"),
    "_esphomelib._tcp.local.": ("ESPHome", "IoT Device"),
    "_homekit._tcp.local.": ("HomeKit", "Smart Home"),
    "_googlecast._tcp.local.": ("Google Cast", "Media Player"),
    "_airplay._tcp.local.": ("AirPlay", "Media Player"),
    "_raop._tcp.local.": ("AirPlay Audio", "Media Player"),
    "_spotify-connect._tcp.local.": ("Spotify Connect", "Media Player"),
    "_ipp._tcp.local.": ("IPP Printer", "Printer"),
    "_ipps._tcp.local.": ("IPPS Printer", "Printer"),
    "_printer._tcp.local.": ("Printer", "Printer"),
    "_pdl-datastream._tcp.local.": ("Printer (JetDirect)", "Printer"),
    "_scanner._tcp.local.": ("Scanner", "Printer"),
    "_uscan._tcp.local.": ("AirScan", "Printer"),
    "_smb._tcp.local.": ("SMB Share", "NAS"),
    "_afpovertcp._tcp.local.": ("AFP Share", "NAS"),
    "_nfs._tcp.local.": ("NFS Share", "NAS"),
    "_ssh._tcp.local.": ("SSH", None),
    "_sftp-ssh._tcp.local.": ("SFTP", None),
    "_workstation._tcp.local.": ("Workstation", "Computer"),
    "_device-info._tcp.local.": ("Device Info", None),
    "_http._tcp.local.": ("HTTP", None),
    "_https._tcp.local.": ("HTTPS", None),
    "_rfb._tcp.local.": ("VNC", None),
    "_companion-link._tcp.local.": ("Apple Companion", None),
    "_sleep-proxy._udp.local.": ("Apple Sleep Proxy", None),
    "_mqtt._tcp.local.": ("MQTT Broker", "Server"),
    "_octoprint._tcp.local.": ("OctoPrint", "3D Printer"),
    "_prusalink._tcp.local.": ("PrusaLink", "3D Printer"),
    "_nvstream._tcp.local.": ("NVIDIA GameStream", "Computer"),
    "_plexmediasvr._tcp.local.": ("Plex", "Media Server"),
    "_jellyfin._tcp.local.": ("Jellyfin", "Media Server"),
    "_hue._tcp.local.": ("Philips Hue", "Smart Home"),
    "_shelly._tcp.local.": ("Shelly", "IoT Device"),
    "_tasmota._tcp.local.": ("Tasmota", "IoT Device"),
    "_wled._tcp.local.": ("WLED", "IoT Device"),
    "_amzn-wplay._tcp.local.": ("Amazon Fire TV", "Smart TV"),
    "_androidtvremote2._tcp.local.": ("Android TV", "Smart TV"),
    "_viziocast._tcp.local.": ("Vizio Cast", "Smart TV"),
    "_roku._tcp.local.": ("Roku", "Smart TV"),
    "_kodi._tcp.local.": ("Kodi", "Media Player"),
    "_adb-tls-connect._tcp.local.": ("ADB", "Computer"),
    "_dgx._tcp.local.": ("NVIDIA DGX", "AI Workstation"),
}


def _decode_txt(props: dict) -> dict[str, str]:
    out = {}
    for k, v in (props or {}).items():
        key = k.decode("utf-8", "replace") if isinstance(k, bytes) else str(k)
        if isinstance(v, bytes):
            v = v.decode("utf-8", "replace")
        out[key] = "" if v is None else str(v)
    return out


class MDNSBackend(DiscoveryBackend):
    name = "mdns"
    requires = ("zeroconf",)

    def __init__(self, service_types: list[str] | None = None):
        self.service_types = service_types

    def discover(self, timeout: float = 6.0) -> list[DiscoveredDevice]:
        from zeroconf import ServiceBrowser, ServiceListener, Zeroconf
        from zeroconf import ZeroconfServiceTypes

        zc = Zeroconf()
        try:
            types = self.service_types
            if types is None:
                # Ask the network which service types exist, then union with the
                # curated list so we still catch types nobody is advertising to
                # the meta-query but that we know to look for.
                found = set(ZeroconfServiceTypes.find(zc=zc, timeout=min(timeout, 4.0)))
                types = sorted(found | set(KNOWN_SERVICES))

            devices: dict[str, DiscoveredDevice] = {}

            class Listener(ServiceListener):
                def add_service(self, zc_, type_, name):
                    info = zc_.get_service_info(type_, name, timeout=1500)
                    if not info:
                        return
                    addrs = []
                    for raw in info.addresses or []:
                        try:
                            a = socket.inet_ntoa(raw)
                        except OSError:
                            continue          # not IPv4 (e.g. an AAAA record)
                        # Loopback/link-local is never a routable device address.
                        # Our own host advertises its .local name on 127.0.0.1;
                        # keeping it minted a bogus "<host>.local @ 127.0.0.1"
                        # device. The host still appears via its real interface.
                        if a.startswith("127.") or a.startswith("169.254."):
                            continue
                        addrs.append(a)
                    ip = addrs[0] if addrs else None
                    if not ip:
                        return

                    label, dtype = KNOWN_SERVICES.get(type_, (type_.split(".")[0].lstrip("_"), None))
                    txt = _decode_txt(info.properties)

                    dev = devices.get(f"ip:{ip}")
                    if dev is None:
                        dev = DiscoveredDevice(source="mdns", ip=ip)
                        devices[f"ip:{ip}"] = dev

                    dev.name = dev.name or (info.server or "").rstrip(".") or name.split(".")[0]
                    dev.device_type = dev.device_type or dtype
                    dev.model = dev.model or txt.get("model") or txt.get("md") or txt.get("ty")
                    dev.vendor = dev.vendor or txt.get("manufacturer") or txt.get("vendor")
                    if label not in dev.services:
                        dev.services.append(label)
                    dev.attributes.setdefault("mdns_records", {})[type_] = {
                        "instance": name.split(".")[0],
                        "port": info.port,
                        "txt": txt,
                        "addresses": addrs,
                    }
                    if type_.startswith(("_matter", "_matterc", "_matterd")):
                        dev.attributes["matter"] = True
                    if type_ == "_hap._tcp.local.":
                        dev.attributes["homekit"] = True

                def update_service(self, *_):  # required by the interface
                    pass

                def remove_service(self, *_):
                    pass

            listener = Listener()
            browsers = [ServiceBrowser(zc, t, listener) for t in types]
            # ponytail: fixed dwell instead of a settle-detector; mDNS answers
            # arrive in the first couple of seconds. Raise timeout on slow VLANs.
            import time

            time.sleep(timeout)
            for b in browsers:
                b.cancel()
            return list(devices.values())
        finally:
            zc.close()


def discover(timeout: float = 6.0) -> list[DiscoveredDevice]:
    return MDNSBackend().safe_discover(timeout=timeout)


if __name__ == "__main__":
    for d in discover(8.0):
        print(f"{d.ip:<16} {d.name or '?':<35} {', '.join(d.services)}")
