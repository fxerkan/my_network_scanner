"""Per-device uptime history — one coloured cell per scheduled scan.

The scan history in `data/scan_history.json` is aggregate: how many devices
were up, not *which*. Answering "has the office printer been flaky this week"
needs a row per device per check, so the scheduler appends one here after every
run and the History page draws it as a strip of cells.

Three states, because two are not enough to be useful:

    up    reachable, nothing flagged
    warn  reachable but not healthy - it was missed by a recent scan, or it
          answered slower than the latency threshold
    down  not reachable

Storage is `data/device_uptime.json`, capped at CAP checks. Device names live
in a side map rather than being repeated in every row, which keeps a month of
five-minute scans well under a megabyte.

    python -m mynes.monitoring.uptime      # self-check
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone

from mynes.paths import data_file

log = logging.getLogger(__name__)

UPTIME_FILE = "device_uptime.json"

# Roughly a day at 5-minute scans, a week at hourly. Past this the strip is
# unreadable anyway and the oldest cells are dropped.
CAP = 288

UP, WARN, DOWN = "up", "warn", "down"


def _identity(device: dict) -> str:
    """Same key the alert rules use, so both sides agree on what a device is."""
    return (device.get("mac") or device.get("ip") or device.get("id") or "").lower()


def _label(device: dict) -> str:
    return device.get("alias") or device.get("hostname") or device.get("ip") or device.get("mac") or "?"


def _is_online(device: dict) -> bool:
    status = device.get("status")
    if isinstance(status, str):
        return status.lower() in ("online", "up", "active", "reachable")
    return bool(device.get("online") or device.get("is_online"))


def _latency(device: dict) -> float | None:
    for container in (device, device.get("attributes") or {}, device.get("telemetry") or {}):
        for key in ("response_time", "latency", "ping_ms", "rtt"):
            value = container.get(key)
            if value is None:
                continue
            try:
                return float(str(value).rstrip("ms "))
            except (TypeError, ValueError):
                continue
    return None


def classify(device: dict, miss_count: int = 0, latency_ms: float = 500) -> str:
    """One device, one check -> up | warn | down. Pure."""
    if not _is_online(device):
        return DOWN
    if miss_count:
        # Answering now but absent from a recent scan: flapping, not healthy.
        return WARN
    latency = _latency(device)
    if latency is not None and latency > latency_ms:
        return WARN
    return UP


# ------------------------------------------------------------------- storage

def load(path: str | None = None) -> dict:
    path = path or data_file(UPTIME_FILE)
    if not os.path.exists(path):
        return {"checks": [], "devices": {}}
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {"checks": [], "devices": {}}
    data.setdefault("checks", [])
    data.setdefault("devices", {})
    return data


def save(data: dict, path: str | None = None) -> None:
    path = path or data_file(UPTIME_FILE)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False)


def record(devices: list, miss_counts: dict | None = None,
           latency_ms: float = 500, path: str | None = None, when: str | None = None) -> dict:
    """Append one check. Returns the row that was written."""
    misses = miss_counts or {}
    data = load(path)

    row = {"ts": when or datetime.now(timezone.utc).isoformat(), "status": {}}
    for device in devices:
        key = _identity(device)
        if not key:
            continue
        row["status"][key] = classify(device, misses.get(key, 0), latency_ms)
        data["devices"][key] = {
            "name": _label(device),
            "ip": device.get("ip"),
            "mac": device.get("mac"),
            "device_type": device.get("device_type"),
        }

    data["checks"].append(row)
    data["checks"] = data["checks"][-CAP:]

    # Forget devices that have not appeared in anything we still keep, so the
    # side map cannot grow forever on a network with rotating BLE addresses.
    seen = {k for check in data["checks"] for k in check["status"]}
    data["devices"] = {k: v for k, v in data["devices"].items() if k in seen}

    save(data, path)
    return row


def series(limit: int = 48, path: str | None = None) -> dict:
    """-> {"checks": [ts...], "devices": [{id, name, cells, uptime, incidents}]}

    `cells` is oldest-first and always `limit` long: checks a device did not
    exist for are `None`, which the UI draws as a blank cell rather than
    claiming it was down before it was ever seen.
    """
    data = load(path)
    checks = data["checks"][-limit:]
    stamps = [c["ts"] for c in checks]

    rows = []
    for key, meta in data["devices"].items():
        cells = [c["status"].get(key) for c in checks]
        seen = [c for c in cells if c]
        if not seen:
            continue
        good = sum(1 for c in seen if c == UP)
        rows.append(
            {
                "id": key,
                "name": meta.get("name") or key,
                "ip": meta.get("ip"),
                "mac": meta.get("mac"),
                "device_type": meta.get("device_type"),
                "cells": cells,
                "checks": len(seen),
                "uptime": round(100 * good / len(seen), 1),
                "incidents": sum(1 for i, c in enumerate(seen) if c == DOWN and (i == 0 or seen[i - 1] != DOWN)),
            }
        )

    # Worst first: a page of green bars is not what anyone opened this for.
    rows.sort(key=lambda r: (r["uptime"], -r["incidents"]))
    return {"checks": stamps, "devices": rows, "total_checks": len(data["checks"])}


def demo():
    """Self-check: classification, capping, and the shape of a series."""
    import tempfile
    from pathlib import Path

    up_dev = {"mac": "AA:BB:CC:00:00:01", "alias": "Pi", "status": "online", "response_time": 12}
    slow = {"mac": "AA:BB:CC:00:00:02", "alias": "Cam", "status": "online", "response_time": 900}
    off = {"mac": "AA:BB:CC:00:00:03", "alias": "TV", "status": "offline"}

    assert classify(up_dev) == UP
    assert classify(slow) == WARN                       # answered, but slowly
    assert classify(off) == DOWN
    assert classify(up_dev, miss_count=1) == WARN       # flapping counts as warn
    assert classify(slow, latency_ms=1000) == UP        # threshold is a knob

    with tempfile.TemporaryDirectory() as tmp:
        path = str(Path(tmp) / "device_uptime.json")

        assert series(path=path)["devices"] == []

        record([up_dev, slow, off], path=path, when="2026-01-01T00:00:00+00:00")
        record([up_dev, slow, off], path=path, when="2026-01-01T00:05:00+00:00")
        record([up_dev, off], path=path, when="2026-01-01T00:10:00+00:00")   # cam missing

        out = series(path=path)
        assert len(out["checks"]) == 3
        by_name = {d["name"]: d for d in out["devices"]}

        assert by_name["Pi"]["cells"] == [UP, UP, UP] and by_name["Pi"]["uptime"] == 100.0
        assert by_name["TV"]["cells"] == [DOWN, DOWN, DOWN] and by_name["TV"]["uptime"] == 0.0
        # A device absent from a check is a gap, not an outage.
        assert by_name["Cam"]["cells"] == [WARN, WARN, None]
        assert by_name["Cam"]["checks"] == 2 and by_name["Cam"]["uptime"] == 0.0

        # Worst first.
        assert out["devices"][0]["name"] in ("TV", "Cam") and out["devices"][-1]["name"] == "Pi"

        # A run of downs is one incident, not three.
        assert by_name["TV"]["incidents"] == 1

        for i in range(CAP + 10):
            record([up_dev], path=path, when=f"2026-02-01T00:{i % 60:02d}:00+00:00")
        assert len(load(path)["checks"]) == CAP

        # Devices that fell off the end of the window are forgotten.
        assert set(load(path)["devices"]) == {_identity(up_dev)}

    print("uptime demo ok")


if __name__ == "__main__":
    demo()
