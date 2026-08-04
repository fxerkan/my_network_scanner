"""Passive DHCP discovery - the same signal Home Assistant's dhcp panel shows.

A DHCP request carries three things no other protocol reliably gives us: the
client MAC, the IP it was handed, and option 12 - the hostname the device
calls *itself*, which is often the only readable name a cheap IoT device ever
emits ("yeelink-light-mono5", "AutoPack_Sweeper").

This is passive: we listen, we never send. That also means a sweep only sees
devices that happen to renew a lease inside the window. HA gets a full table
because it listens permanently; the honest place for that here is the
background monitor, not an 8-second sweep. `available()` says so.
"""

from __future__ import annotations

from mynes.discovery.base import DiscoveredDevice, DiscoveryBackend


def _hostname(bootp_options) -> str | None:
    for opt in bootp_options or []:
        if isinstance(opt, tuple) and opt[0] == "hostname":
            value = opt[1]
            return value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)
    return None


def _requested_ip(bootp_options) -> str | None:
    for opt in bootp_options or []:
        if isinstance(opt, tuple) and opt[0] == "requested_addr":
            return str(opt[1])
    return None


def _mac(chaddr: bytes) -> str:
    return ":".join(f"{b:02x}" for b in chaddr[:6])


class DHCPBackend(DiscoveryBackend):
    name = "dhcp"
    requires = ("scapy",)

    def available(self) -> tuple[bool, str]:
        ok, reason = super().available()
        if not ok:
            return ok, reason
        from mynes.core.arp import has_raw_socket_privilege

        if not has_raw_socket_privilege():
            return False, "needs raw-socket privileges to sniff DHCP traffic"
        return True, "passive: sees only devices that renew a lease during the sweep"

    def discover(self, timeout: float = 5.0) -> list[DiscoveredDevice]:
        from scapy.all import BOOTP, DHCP, sniff  # noqa: PLC0415 - optional dependency

        found: dict[str, DiscoveredDevice] = {}

        def collect(pkt):
            if not pkt.haslayer(BOOTP):
                return
            bootp = pkt[BOOTP]
            mac = _mac(bytes(bootp.chaddr))
            options = pkt[DHCP].options if pkt.haslayer(DHCP) else []
            ip = _requested_ip(options) or (
                str(bootp.yiaddr) if str(bootp.yiaddr) != "0.0.0.0" else None
            ) or (str(bootp.ciaddr) if str(bootp.ciaddr) != "0.0.0.0" else None)
            name = _hostname(options)

            dev = found.get(mac)
            if dev is None:
                dev = DiscoveredDevice(source="dhcp", mac=mac, services=["DHCP"])
                found[mac] = dev
            dev.ip = dev.ip or ip
            dev.name = dev.name or name
            if name:
                dev.attributes.setdefault("dhcp", {})["hostname"] = name

        sniff(filter="udp and (port 67 or port 68)", timeout=timeout, store=False, prn=collect)
        return list(found.values())


def discover(timeout: float = 5.0) -> list[DiscoveredDevice]:
    return DHCPBackend().safe_discover(timeout=timeout)


def demo() -> None:
    opts = [("message-type", 3), ("hostname", b"yeelink-light-mono5"),
            ("requested_addr", "192.168.1.30"), "end"]
    assert _hostname(opts) == "yeelink-light-mono5"
    assert _requested_ip(opts) == "192.168.1.30"
    assert _hostname([("message-type", 3), "end"]) is None
    assert _mac(bytes.fromhex("aabbcc010203") + b"\x00" * 10) == "aa:bb:cc:01:02:03"
    print("dhcp demo ok")


if __name__ == "__main__":
    demo()
    for d in discover(20.0):
        print(f"{d.mac}  {d.ip or '?':<16} {d.name or ''}")
