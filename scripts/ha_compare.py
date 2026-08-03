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


def load_devices(scan_range: str | None) -> list[dict]:
    from mynes.core.scanner import LANScanner

    scanner = LANScanner()
    if scan_range:
        print(f"Scanning {scan_range} ...", file=sys.stderr)
        scanner.scan_network(ip_range=scan_range, include_offline=False)
    else:
        scanner.load_from_json()
    devices = scanner.get_devices()
    return list(devices.values()) if isinstance(devices, dict) else (devices or [])


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scan", metavar="CIDR", help="run a fresh scan of this range first")
    ap.add_argument("--redact", action="store_true", help="hash IPs/MACs so the output is shareable")
    ap.add_argument("--json", action="store_true", help="emit raw JSON instead of a table")
    args = ap.parse_args()

    client = HomeAssistantClient()
    if not client.configured():
        sys.exit("Set MYNES_HA_URL and MYNES_HA_TOKEN first. See the docstring at the top of this file.")

    ping = client.ping()
    if not ping.get("ok"):
        sys.exit(f"Cannot reach Home Assistant: {ping.get('error')}")
    print(f"Home Assistant : {ping.get('location_name') or client.url} (core {ping.get('version', '?')})")

    devices = load_devices(args.scan)
    result = client.compare(devices)

    if args.json:
        print(json.dumps(result, indent=2, default=str))
        return

    show = redact if args.redact else (lambda v: v or "-")

    print(f"MyNeS devices  : {result['mynes_total']}")
    print(f"HA entities    : {result['home_assistant_total']}")
    print(f"Matched        : {result['in_both']}")
    print(f"Only in HA     : {len(result['only_in_home_assistant'])}")
    print(f"Only in MyNeS  : {len(result['only_in_mynes'])}")

    print("\nHA entities by domain:")
    for domain, count in result["by_domain"].items():
        print(f"  {count:>4}  {domain}")

    print("\nHA source types (how HA learned about the device):")
    for source, count in result["by_source_type"].items():
        print(f"  {count:>4}  {source}")

    print("\n--- Only Home Assistant sees these (Zigbee / Z-Wave / Matter / cloud) ---")
    for d in result["only_in_home_assistant"][:80]:
        print(f"  {d['entity_id'][:46]:<48}{(d.get('name') or '')[:28]:<30}{d.get('state', '')}")
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
