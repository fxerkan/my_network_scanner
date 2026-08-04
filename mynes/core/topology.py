"""Who is plugged into what.

An unmanaged L2 switch is invisible. It does not answer ARP on behalf of the
devices behind it and it does not decrement TTL, so nothing on the wire says a
Raspberry Pi hangs off a TP-Link switch rather than off the router. The same is
true of an access point in bridge mode. Three things we *can* establish:

  * routed hops - traceroute finds a real parent whenever a device sits behind
    something that routes instead of bridging (a second router, a mesh node in
    router mode, a device on another subnet),
  * which devices are infrastructure at all (router, modem, switch, AP,
    extender), from their detected type,
  * whatever the user tells us - the only source that can see through a bridge.

The tree is built from those three, manual first. Nothing is invented: a device
we know nothing about hangs off the gateway, which is exactly where it sits at
layer 3, and every edge carries the source it came from so the UI can say so.

    python -m mynes.core.topology            # self-check
    python -m mynes.core.topology 192.168.1.0/24   # live traceroute sweep
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

from mynes.paths import data_file

# Types that can legitimately be somebody's uplink.
INFRA_TYPES = {
    "Router", "Modem", "Switch", "Access Point", "Repeater", "Extender", "Gateway",
}

UPLINKS_FILE = "topology.json"


def is_infra(device: dict) -> bool:
    """True for a device that other devices could plausibly hang off."""
    dtype = (device.get("device_type") or "").strip()
    if dtype in INFRA_TYPES:
        return True
    return bool(re.search(r"router|switch|access point|extender|repeater|modem", dtype, re.I))


# ---------------------------------------------------------------- persistence

def load_state(path: str | None = None) -> dict:
    """{"uplinks": {child: parent}} set by hand, {"traced": ...} last sweep."""
    path = path or data_file(UPLINKS_FILE)
    state = {"uplinks": {}, "traced": {}}
    if not os.path.exists(path):
        return state
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return state
    for key in state:
        state[key] = {k: v for k, v in (data.get(key) or {}).items() if v}
    return state


def save_state(state: dict, path: str | None = None) -> dict:
    path = path or data_file(UPLINKS_FILE)
    clean = {key: {k: v for k, v in (state.get(key) or {}).items() if v}
             for key in ("uplinks", "traced")}
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(clean, fh, ensure_ascii=False, indent=2)
    return clean


# ------------------------------------------------------------------- traceroute

_HOP_IP = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def trace_parent(ip: str, timeout: float = 6.0) -> str | None:
    """Last hop before `ip`, or None when the device is one hop away.

    One hop away is the normal answer on a home LAN and is not a failure: it
    means "directly reachable at layer 3", switches and bridges included.
    """
    if sys.platform == "win32":
        cmd = ["tracert", "-d", "-h", "5", "-w", "800", ip]
    else:
        cmd = ["traceroute", "-n", "-q", "1", "-w", "1", "-m", "5", ip]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except (OSError, subprocess.SubprocessError):
        return None   # no traceroute binary, or it died - degrade, do not raise

    hops = []
    for line in out.splitlines()[1:]:          # first line is the banner
        found = _HOP_IP.findall(line)
        # Skip the header's copy of the target and unreachable "* * *" hops.
        hop = next((h for h in found if h != ip), None)
        if hop and hop not in hops:
            hops.append(hop)
    return hops[-1] if hops else None


def discover_uplinks(devices: list, workers: int = 8, timeout: float = 6.0) -> dict:
    """Traceroute every device in parallel; keep only the multi-hop answers."""
    targets = [d.get("ip") for d in devices if d.get("ip")]
    found = {}
    if not targets:
        return found
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for ip, parent in zip(targets, pool.map(lambda t: trace_parent(t, timeout), targets)):
            if parent and parent != ip:
                found[ip] = parent
    return found


# ------------------------------------------------------------------ tree build

def build_tree(devices: list, gateway_ip: str | None = None,
               uplinks: dict | None = None, traced: dict | None = None) -> dict:
    """-> {"gateway": ip|None, "nodes": [{ip, parent, source, infra, ...}]}.

    source is one of: "gateway" (this IS the gateway), "manual", "traceroute",
    "default" (assumed direct, because nothing said otherwise).
    """
    uplinks = uplinks or {}
    traced = traced or {}
    by_ip = {d["ip"]: d for d in devices if d.get("ip")}

    if gateway_ip not in by_ip:
        # Fall back to whatever infra device looks most like a gateway.
        gateway_ip = next(
            (ip for ip, d in by_ip.items() if is_infra(d) and ip.endswith(".1")),
            next((ip for ip, d in by_ip.items() if is_infra(d)), None),
        )

    nodes = []
    for device in devices:
        ip = device.get("ip")
        if not ip:
            nodes.append({**device, "parent": None, "source": "radio", "infra": False})
            continue
        if ip == gateway_ip:
            parent, source = None, "gateway"
        elif uplinks.get(ip) in by_ip and uplinks[ip] != ip:
            parent, source = uplinks[ip], "manual"
        elif traced.get(ip) in by_ip and traced[ip] != ip:
            parent, source = traced[ip], "traceroute"
        else:
            parent, source = gateway_ip, "default"
        nodes.append({**device, "parent": parent, "source": source, "infra": is_infra(device)})

    _break_cycles(nodes, gateway_ip)
    return {"gateway": gateway_ip, "nodes": nodes}


def _break_cycles(nodes: list, gateway_ip: str | None) -> None:
    """A hand-assigned uplink can point in a circle. Reparent to the gateway."""
    parent_of = {n["ip"]: n.get("parent") for n in nodes if n.get("ip")}
    for node in nodes:
        seen, cur = {node.get("ip")}, node.get("parent")
        while cur:
            if cur in seen:
                node["parent"] = gateway_ip if node.get("ip") != gateway_ip else None
                node["source"] = "default"
                break
            seen.add(cur)
            cur = parent_of.get(cur)


def demo():
    """Self-check of the pure half: no traceroute, no files, no network."""
    devices = [
        {"ip": "192.168.1.1", "device_type": "Router"},
        {"ip": "192.168.1.2", "device_type": "Switch"},
        {"ip": "192.168.1.10", "device_type": "Raspberry Pi Server"},
        {"ip": "192.168.2.5", "device_type": "Laptop"},
        {"mac": "AA:BB:CC:DD:EE:FF", "device_type": "Smart Light"},
    ]

    assert is_infra(devices[0]) and is_infra(devices[1])
    assert not is_infra(devices[2])

    tree = build_tree(devices, "192.168.1.1")
    by_ip = {n.get("ip"): n for n in tree["nodes"]}
    assert tree["gateway"] == "192.168.1.1"
    assert by_ip["192.168.1.1"]["parent"] is None
    assert by_ip["192.168.1.10"]["parent"] == "192.168.1.1"
    assert by_ip["192.168.1.10"]["source"] == "default"
    assert by_ip[None]["source"] == "radio"          # the BLE bulb, no IP

    # A hand-assigned uplink beats the traced one, which beats the default.
    tree = build_tree(devices, "192.168.1.1",
                      uplinks={"192.168.1.10": "192.168.1.2"},
                      traced={"192.168.1.10": "192.168.1.1", "192.168.2.5": "192.168.1.2"})
    by_ip = {n.get("ip"): n for n in tree["nodes"]}
    assert by_ip["192.168.1.10"]["parent"] == "192.168.1.2"
    assert by_ip["192.168.1.10"]["source"] == "manual"
    assert by_ip["192.168.2.5"]["parent"] == "192.168.1.2"
    assert by_ip["192.168.2.5"]["source"] == "traceroute"

    # An uplink pointing at an unknown device is ignored, not honoured.
    tree = build_tree(devices, "192.168.1.1", uplinks={"192.168.1.10": "10.0.0.9"})
    assert {n.get("ip"): n for n in tree["nodes"]}["192.168.1.10"]["parent"] == "192.168.1.1"

    # ...and a circular one gets cut instead of hanging the renderer.
    tree = build_tree(devices, "192.168.1.1",
                      uplinks={"192.168.1.2": "192.168.1.10", "192.168.1.10": "192.168.1.2"})
    by_ip = {n.get("ip"): n for n in tree["nodes"]}
    assert by_ip["192.168.1.2"]["parent"] == "192.168.1.1"
    assert by_ip["192.168.1.10"]["parent"] == "192.168.1.1"

    # Gateway not in the list: pick the infra device that looks like one.
    tree = build_tree(devices[1:], None)
    assert tree["gateway"] == "192.168.1.2"

    # Round-trip through disk, empty values dropped on the way out.
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "topology.json")
        assert load_state(path) == {"uplinks": {}, "traced": {}}
        save_state({"uplinks": {"a": "b", "c": None}, "traced": {}}, path)
        assert load_state(path)["uplinks"] == {"a": "b"}

    print("topology demo ok")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        from mynes.core.network import get_default_gateway
        from mynes.core.scanner import LANScanner

        scanner = LANScanner()
        scanner.scan_network(sys.argv[1])
        found = scanner.get_devices()
        found = list(found.values()) if isinstance(found, dict) else found
        traced = discover_uplinks(found)
        print(json.dumps(build_tree(found, get_default_gateway(), traced=traced), indent=2))
    else:
        demo()
