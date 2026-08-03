#!/usr/bin/env python3
"""Compare what Home Assistant knows against what MyNeS finds.

Your token never leaves this machine: it is read from the environment, used for
local HTTP calls to your own HA instance, and never written to disk.

    export MYNES_HA_URL="http://192.168.1.116:8123"
    export MYNES_HA_TOKEN="..."          # HA -> profile -> Security -> Long-lived access tokens
    .venv/bin/python scripts/ha_compare.py

    # Scan first (slower, but compares against a fresh sweep):
    .venv/bin/python scripts/ha_compare.py --scan 192.168.1.0/24

    # Redact MACs/IPs before sharing the output:
    .venv/bin/python scripts/ha_compare.py --redact
"""

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mynes.integrations.home_assistant import HomeAssistantClient  # noqa: E402


def redact(value: str | None) -> str:
    if not value:
        return "-"
    return "x" + hashlib.sha256(value.encode()).hexdigest()[:8]


def load_devices(scan_range: str | None, with_discovery: bool = True) -> list[dict]:
    from mynes.core.scanner import LANScanner

    scanner = LANScanner()
    if scan_range:
        print(f"Scanning {scan_range} ...", file=sys.stderr)
        scanner.scan_network(ip_range=scan_range, include_offline=False)
    else:
        scanner.load_from_json()
    devices = scanner.get_devices()
    devices = list(devices.values()) if isinstance(devices, dict) else (devices or [])

    if not with_discovery:
        return devices

    # An IP scan names a device after its vendor ("TP-Link IoT Device"); mDNS
    # names it "rpifx.local". Home Assistant uses the latter, so without this
    # the name-matching half of the diff finds almost nothing.
    print("Running a discovery sweep for hostnames ...", file=sys.stderr)
    try:
        from mynes.discovery import discover_all

        found = discover_all(timeout=8).get("devices", [])
    except Exception as e:  # noqa: BLE001 - discovery is a bonus, never fatal here
        print(f"  (discovery skipped: {e})", file=sys.stderr)
        return devices

    by_ip = {d.get("ip"): d for d in devices if d.get("ip")}
    for extra in found:
        target = by_ip.get(extra.get("ip"))
        if target is not None and extra.get("name"):
            target.setdefault("hostname", extra["name"])
            target["discovery_name"] = extra["name"]
        elif target is None and extra.get("mac"):
            devices.append({
                "mac": extra.get("mac"), "ip": extra.get("ip"),
                "hostname": extra.get("name"), "alias": extra.get("name"),
                "vendor": extra.get("vendor"), "device_type": extra.get("device_type"),
                "status": "online", "discovery_sources": extra.get("sources", []),
            })
    return devices


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scan", metavar="CIDR", help="run a fresh scan of this range first")
    ap.add_argument("--redact", action="store_true", help="hash IPs/MACs so the output is shareable")
    ap.add_argument("--json", action="store_true", help="emit raw JSON instead of a table")
    ap.add_argument("--no-discovery", action="store_true",
                    help="skip the mDNS/SSDP/BLE sweep used to recover hostnames")
    args = ap.parse_args()

    client = HomeAssistantClient()
    if not client.configured():
        sys.exit("Set MYNES_HA_URL and MYNES_HA_TOKEN first. See the docstring at the top of this file.")

    ping = client.ping()
    if not ping.get("ok"):
        sys.exit(f"Cannot reach Home Assistant: {ping.get('error')}")
    print(f"Home Assistant : {ping.get('location_name') or client.url} (core {ping.get('version', '?')})")

    devices = load_devices(args.scan, with_discovery=not args.no_discovery)
    result = client.compare(devices)

    if args.json:
        print(json.dumps(result, indent=2, default=str))
        return

    show = redact if args.redact else (lambda v: v or "-")

    print(f"Data source    : {result['source']}"
          + ("  (Zigbee/Matter/BLE included)" if result["source"] == "device_registry"
             else "  (entity states only - install websocket-client to see radio devices)"))
    print(f"MyNeS devices  : {result['mynes_total']}")
    print(f"HA devices     : {result['home_assistant_total']}"
          + (f"  (+{result['home_assistant_excluded']} services/helpers excluded)"
             if result.get("home_assistant_excluded") else ""))
    print(f"Matched        : {result['in_both']}")
    print(f"Only in HA     : {len(result['only_in_home_assistant'])}")
    print(f"Only in MyNeS  : {len(result['only_in_mynes'])}")

    if result.get("by_protocol"):
        print("\nHA devices by transport (what MyNeS could ever see):")
        for proto, count in result["by_protocol"].items():
            reach = {
                "Zigbee": "needs the Zigbee2MQTT/ZHA bridge",
                "Z-Wave": "needs the Z-Wave JS bridge",
                "Thread": "needs a Thread border router",
                "Matter": "visible over mDNS",
                "Bluetooth": "visible to the BLE backend",
                "Cloud": "no local footprint - invisible by design",
                "IP": "should appear in a network scan",
                "MQTT": "visible via the MQTT backend",
                "Companion app": "a phone, appears as an IP device",
            }.get(proto, "")
            print(f"  {count:>4}  {proto:<16}{reach}")

    print("\n--- Only Home Assistant sees these ---")
    for d in result["only_in_home_assistant"][:80]:
        if "entity_id" in d:
            print(f"  {d['entity_id'][:46]:<48}{(d.get('name') or '')[:28]:<30}{d.get('state', '')}")
        else:
            label = (d.get("name") or "(unnamed)")[:34]
            meta = " ".join(filter(None, [d.get("manufacturer"), d.get("model")]))[:32]
            print(f"  {(d.get('protocol') or '?'):<16}{label:<36}{meta}")
    if len(result["only_in_home_assistant"]) > 80:
        print(f"  ... and {len(result['only_in_home_assistant']) - 80} more")

    print("\n--- Only MyNeS sees these (on the network, unknown to HA) ---")
    for d in result["only_in_mynes"][:80]:
        print(f"  {show(d.get('ip')):<18}{show(d.get('mac')):<20}"
              f"{(d.get('vendor') or '?')[:26]:<28}{(d.get('hostname') or d.get('alias') or '')[:26]}")
    if len(result["only_in_mynes"]) > 80:
        print(f"  ... and {len(result['only_in_mynes']) - 80} more")


if __name__ == "__main__":
    main()
