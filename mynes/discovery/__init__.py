"""Multi-protocol discovery: run every backend in parallel, merge by identity.

    from mynes.discovery import discover_all
    result = discover_all(timeout=8)

Each backend is optional and independently fault-tolerant: a missing dependency
or an unreachable broker degrades that protocol to zero results instead of
failing the sweep.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from mynes.discovery.base import DiscoveredDevice, DiscoveryBackend
from mynes.discovery.bluetooth import BluetoothBackend
from mynes.discovery.mdns import MDNSBackend
from mynes.discovery.mqtt import MQTTBackend
from mynes.discovery.onvif import ONVIFBackend
from mynes.discovery.ssdp import SSDPBackend

__all__ = [
    "DiscoveredDevice",
    "DiscoveryBackend",
    "BluetoothBackend",
    "MDNSBackend",
    "MQTTBackend",
    "ONVIFBackend",
    "SSDPBackend",
    "backends",
    "discover_all",
]


def backends(enabled: list[str] | None = None) -> list[DiscoveryBackend]:
    all_backends = [MDNSBackend(), SSDPBackend(), ONVIFBackend(), MQTTBackend(),
                    BluetoothBackend()]
    if enabled is None:
        return all_backends
    return [b for b in all_backends if b.name in enabled]


def _merge(devices: list[DiscoveredDevice]) -> list[dict]:
    merged: dict[str, dict] = {}
    for dev in devices:
        key = dev.key()
        row = merged.get(key)
        if row is None:
            row = dev.to_dict()
            row["sources"] = [row.pop("source")]
            merged[key] = row
            continue

        if dev.source not in row["sources"]:
            row["sources"].append(dev.source)
        for field in ("ip", "mac", "name", "model", "vendor", "device_type"):
            row[field] = row.get(field) or getattr(dev, field)
        row["services"] = sorted(set(row["services"]) | set(dev.services))
        row["attributes"] = {**dev.attributes, **row["attributes"]}
    return list(merged.values())


def discover_all(timeout: float = 8.0, enabled: list[str] | None = None) -> dict:
    """Run the selected backends concurrently and return merged results.

    Returns {"devices": [...], "protocols": {name: {count, status, detail}}}
    """
    selected = backends(enabled)
    found: list[DiscoveredDevice] = []
    protocols: dict[str, dict] = {}

    with ThreadPoolExecutor(max_workers=max(len(selected), 1)) as pool:
        futures = {pool.submit(b.safe_discover, timeout): b for b in selected}
        for fut, backend in futures.items():
            ok, reason = backend.available()
            results = fut.result()
            found.extend(results)
            protocols[backend.name] = {
                "count": len(results),
                "status": "ok" if ok else "skipped",
                "detail": reason,
            }

    return {"devices": _merge(found), "protocols": protocols}


if __name__ == "__main__":
    import json

    print(json.dumps(discover_all(8.0), indent=2, default=str))
