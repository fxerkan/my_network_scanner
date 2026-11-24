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


def _vendor_class(bootp_options) -> str | None:
    for opt in bootp_options or []:
        if isinstance(opt, tuple) and opt[0] == "vendor_class_id":
            value = opt[1]
            return value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)
    return None


# ---------------------------------------------------------------------------
# Permanent listener - the only way to learn every device's own hostname
# ---------------------------------------------------------------------------
# A sweep-time sniff sees only the leases renewed in those few seconds. Run
# for the app's lifetime instead and remember what every MAC called itself;
# over a day (one lease period) the table fills in for the whole LAN. That is
# exactly where names like "Petkit_T4", "L510", "C200C" or "Ebru-Pixel-10"
# come from - most IoT devices emit no readable name anywhere else.

STORE_FILE = "dhcp_hosts.json"
_listener = None


class DhcpListener:
    def __init__(self, save_every: float = 30.0):
        import threading
        self._lock = threading.Lock()
        self.table: dict = {}
        self.save_every = save_every
        self._dirty = False
        self._last_save = 0.0
        self.thread = None
        self.error = None
        try:
            from mynes.paths import load_local
            self.table = load_local(STORE_FILE) or {}
        except Exception:  # noqa: BLE001
            self.table = {}

    def record(self, mac: str, hostname: str | None, ip: str | None, vendor_class: str | None) -> None:
        import time
        from datetime import datetime
        if not mac or not (hostname or vendor_class):
            return
        with self._lock:
            entry = self.table.setdefault(mac.lower(), {})
            changed = False
            for key, value in (("hostname", hostname), ("ip", ip), ("vendor_class", vendor_class)):
                if value and entry.get(key) != value:
                    entry[key] = value
                    changed = True
            entry["seen"] = datetime.now().isoformat(timespec="seconds")
            self._dirty = self._dirty or changed
            if self._dirty and time.monotonic() - self._last_save > self.save_every:
                self._save()

    def _save(self) -> None:
        import time
        try:
            from mynes.paths import save_local
            save_local(STORE_FILE, dict(self.table))
            self._dirty = False
            self._last_save = time.monotonic()
        except Exception:  # noqa: BLE001
            pass

    def lookup(self, mac: str | None) -> dict:
        if not mac:
            return {}
        with self._lock:
            return dict(self.table.get(mac.lower()) or {})

    def _loop(self) -> None:
        try:
            from scapy.all import BOOTP, DHCP, sniff  # noqa: PLC0415

            def collect(pkt):
                if not pkt.haslayer(BOOTP) or not pkt.haslayer(DHCP):
                    return
                bootp = pkt[BOOTP]
                if bootp.op != 1:            # client -> server only: the name is the client's own
                    return
                options = pkt[DHCP].options
                ip = _requested_ip(options) or (str(bootp.ciaddr) if str(bootp.ciaddr) != "0.0.0.0" else None)
                self.record(_mac(bytes(bootp.chaddr)), _hostname(options), ip, _vendor_class(options))

            sniff(filter="udp and (port 67 or port 68)", store=False, prn=collect)
        except Exception as e:  # noqa: BLE001 - optional feature, never fatal
            self.error = f"{type(e).__name__}: {e}"

    def start(self):
        import threading
        ok, why = DHCPBackend().available()
        if not ok:
            self.error = why
            return self
        self.thread = threading.Thread(target=self._loop, name="mynes-dhcp-listener", daemon=True)
        self.thread.start()
        return self


def start_listener() -> DhcpListener:
    """Start the process-wide listener once (idempotent)."""
    global _listener
    if _listener is None:
        _listener = DhcpListener().start()
    return _listener


def lookup(mac: str | None) -> dict:
    """mac -> {"hostname", "ip", "vendor_class", "seen"} from the listener,
    or from the persisted table when the listener is not running."""
    if _listener is not None:
        return _listener.lookup(mac)
    try:
        from mynes.paths import load_local
        return dict((load_local(STORE_FILE) or {}).get((mac or "").lower()) or {})
    except Exception:  # noqa: BLE001
        return {}


def demo() -> None:
    opts = [("message-type", 3), ("hostname", b"yeelink-light-mono5"),
            ("requested_addr", "192.168.1.30"), "end"]
    assert _hostname(opts) == "yeelink-light-mono5"
    assert _requested_ip(opts) == "192.168.1.30"
    assert _hostname([("message-type", 3), "end"]) is None
    assert _mac(bytes.fromhex("aabbcc010203") + b"\x00" * 10) == "aa:bb:cc:01:02:03"
    assert _vendor_class([("vendor_class_id", b"android-dhcp-14"), "end"]) == "android-dhcp-14"
    lst = DhcpListener.__new__(DhcpListener)
    import threading
    lst._lock, lst.table, lst._dirty, lst._last_save, lst.save_every = threading.Lock(), {}, False, 0.0, 1e9
    lst.record("AA:BB:CC:00:00:01", "Petkit_T4", "192.168.1.109", None)
    assert lst.lookup("aa:bb:cc:00:00:01")["hostname"] == "Petkit_T4"
    print("dhcp demo ok")


if __name__ == "__main__":
    demo()
    for d in discover(20.0):
        print(f"{d.mac}  {d.ip or '?':<16} {d.name or ''}")
