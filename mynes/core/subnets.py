"""Which subnet each device actually sits in.

A home LAN grown past one router is not one flat /24 any more: a Docker host
runs half a dozen bridge networks, an IoT VLAN sits behind the same physical
switch as the trusted one, and a lab has a management network on a second
NIC. ``lan_devices.json`` only ever recorded a bare IP - there was no way to
tell "this /24" from "that /24" apart once devices from more than one scan
piled up in the same list, and the topology graph drew them as one flat mesh.

This module answers one question, cheaply and without touching the network:
given a device's IP and the CIDRs we already know about (from the host's own
interfaces, from Docker, or from every other device's IP so far), which
subnet does it belong to? Nothing here calls out to the network - it is pure
grouping logic over data the scanner already collected, so it is the cheapest
layer and the one to test first.

    python -m mynes.core.subnets            # self-check
"""

from __future__ import annotations

import ipaddress
import sys

# Devices land in this bucket when their address cannot be parsed at all
# (radio-only devices with no IP, or malformed data). Grouped, not dropped.
NO_IP_KEY = "no-ip"


def _parse(cidr_or_ip: str):
    try:
        return ipaddress.ip_address(cidr_or_ip)
    except ValueError:
        return None


def known_subnets_from_interfaces(interfaces: list) -> list:
    """Interface/Docker-network dicts (as ``get_available_networks()`` returns)
    -> a deduplicated list of ``{"cidr": ..., "label": ..., "type": ...}``.

    Every entry already carries a ``network_range`` (CIDR string) and a
    ``type`` ("WiFi", "Ethernet", "Docker Network", ...) - this just narrows
    that down to what subnet grouping needs and drops duplicates from
    multiple interfaces that happen to share a range.
    """
    seen = {}
    for iface in interfaces or []:
        cidr = iface.get("network_range") or iface.get("cidr") or iface.get("network")
        if not cidr:
            continue
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        key = str(network)
        if key in seen:
            continue
        seen[key] = {
            "cidr": key,
            "label": iface.get("description") or iface.get("interface") or key,
            "type": iface.get("type") or "Other",
        }
    return list(seen.values())


def subnet_for_ip(ip: str, known_subnets: list | None = None,
                   fallback_prefix: int = 24) -> dict:
    """Best-guess subnet for one IP.

    A known interface/Docker CIDR that actually contains the address wins -
    that is ground truth, not a guess. Absent that (a device reached through
    a router we did not scan from, or historical data from an old scan),
    fall back to the address's own /24: wrong for anyone running unusual
    masks, but a stable, deterministic bucket beats no grouping at all, and
    it is labelled "guessed" so the UI can say so.
    """
    addr = _parse(ip)
    if addr is None:
        return {"cidr": NO_IP_KEY, "label": "No IP (radio)", "type": "radio", "known": False}

    for subnet in known_subnets or []:
        try:
            network = ipaddress.ip_network(subnet["cidr"], strict=False)
        except (ValueError, KeyError, TypeError):
            continue
        if addr.version == network.version and addr in network:
            return {**subnet, "known": True}

    guessed = ipaddress.ip_network(f"{ip}/{fallback_prefix}", strict=False)
    return {"cidr": str(guessed), "label": str(guessed), "type": "guessed", "known": False}


def group_devices_by_subnet(devices: list, known_subnets: list | None = None) -> dict:
    """-> ``{cidr: {"label", "type", "known", "devices": [...], "gateway_ip"}}``.

    ``gateway_ip`` is the lowest usable address actually present among the
    subnet's own devices' addresses when it looks like infrastructure,
    otherwise the subnet's own network address + 1 - a guess, but a stable
    one for drawing an edge from the group to its likely uplink.
    """
    from mynes.core.topology import is_infra

    groups: dict = {}
    for device in devices:
        ip = device.get("ip")
        subnet = subnet_for_ip(ip, known_subnets)
        key = subnet["cidr"]
        if key not in groups:
            groups[key] = {**subnet, "devices": []}
        groups[key]["devices"].append(device)

    for key, group in groups.items():
        if key == NO_IP_KEY:
            group["gateway_ip"] = None
            continue
        infra_ips = sorted(
            d["ip"] for d in group["devices"] if d.get("ip") and is_infra(d)
        )
        if infra_ips:
            group["gateway_ip"] = infra_ips[0]
        else:
            try:
                network = ipaddress.ip_network(key, strict=False)
                group["gateway_ip"] = str(network.network_address + 1) if network.num_addresses > 2 else None
            except ValueError:
                group["gateway_ip"] = None

    return groups


def subnet_summary(devices: list, known_subnets: list | None = None) -> list:
    """One row per subnet, sorted largest-first - what the UI's breakdown list needs."""
    groups = group_devices_by_subnet(devices, known_subnets)
    rows = []
    for cidr, group in groups.items():
        rows.append({
            "cidr": cidr,
            "label": group["label"],
            "type": group["type"],
            "known": group["known"],
            "gateway_ip": group.get("gateway_ip"),
            "device_count": len(group["devices"]),
            "online_count": sum(1 for d in group["devices"] if d.get("status") == "online"),
        })
    rows.sort(key=lambda r: r["device_count"], reverse=True)
    return rows


def demo():
    """Self-check: no network, no files."""
    interfaces = [
        {"network_range": "192.168.1.0/24", "interface": "eth0", "type": "Ethernet"},
        {"network_range": "192.168.1.0/24", "interface": "eth0-dup", "type": "Ethernet"},
        {"network_range": "172.17.0.0/16", "interface": "docker0", "type": "Docker"},
    ]
    known = known_subnets_from_interfaces(interfaces)
    assert len(known) == 2, known   # the duplicate CIDR collapses to one entry
    assert {"192.168.1.0/24", "172.17.0.0/16"} == {s["cidr"] for s in known}

    # A device inside a known interface subnet is matched to it exactly.
    hit = subnet_for_ip("192.168.1.42", known)
    assert hit["cidr"] == "192.168.1.0/24" and hit["known"] is True

    # A device on a subnet nobody scanned from falls back to its own /24,
    # marked as a guess rather than silently pretending it is ground truth.
    guess = subnet_for_ip("10.9.9.9", known)
    assert guess["cidr"] == "10.9.9.0/24" and guess["known"] is False

    # A radio device with no IP lands in its own bucket instead of crashing.
    no_ip = subnet_for_ip(None, known)
    assert no_ip["cidr"] == NO_IP_KEY

    devices = [
        {"ip": "192.168.1.1", "device_type": "Router", "status": "online"},
        {"ip": "192.168.1.10", "device_type": "Raspberry Pi Server", "status": "online"},
        {"ip": "172.17.0.2", "device_type": "Docker Container", "status": "online"},
        {"ip": "10.5.5.5", "device_type": "Unknown", "status": "offline"},
        {"mac": "AA:BB:CC:DD:EE:FF", "device_type": "Smart Bulb", "status": "online"},
    ]
    groups = group_devices_by_subnet(devices, known)
    assert set(groups) == {"192.168.1.0/24", "172.17.0.0/16", "10.5.5.0/24", NO_IP_KEY}
    assert len(groups["192.168.1.0/24"]["devices"]) == 2
    # The known LAN's gateway is the router actually seen on it, not a guess.
    assert groups["192.168.1.0/24"]["gateway_ip"] == "192.168.1.1"
    # A subnet with no infra device seen yet falls back to .0/24's .1 guess.
    assert groups["10.5.5.0/24"]["gateway_ip"] == "10.5.5.1"
    assert groups[NO_IP_KEY]["gateway_ip"] is None

    summary = subnet_summary(devices, known)
    assert summary[0]["cidr"] == "192.168.1.0/24"          # largest group first
    assert summary[0]["device_count"] == 2
    assert summary[0]["online_count"] == 2

    print("subnets demo ok")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        import json

        from mynes.core.network import get_available_networks
        from mynes.core.scanner import LANScanner

        scanner = LANScanner()
        scanner.scan_network(ip_range=sys.argv[1])
        known = known_subnets_from_interfaces(scanner.get_available_networks())
        print(json.dumps(subnet_summary(scanner.get_devices(), known), indent=2))
    else:
        demo()
