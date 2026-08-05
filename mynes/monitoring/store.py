"""Alert history on disk: a capped, newest-first JSON list.

ponytail: a JSON file, not SQLite. A home network produces a handful of alerts a
day; swap in SQLite only if the file grows past a few MB or multiple writers appear.
"""

from __future__ import annotations

import json
import os
import threading

from mynes.paths import data_file

ALERTS_FILE = data_file("alerts.json")
STATE_FILE = data_file("monitor_state.json")
MAX_ALERTS = 1000

_lock = threading.Lock()


def _read(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def _write(path, payload):
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False, default=str)
    os.replace(tmp, path)  # atomic: a crash mid-write cannot truncate the history


def filter_alerts(severity: str | None = None, unread_only: bool = False,
                  rule: str | None = None, query: str | None = None) -> list[dict]:
    """Every alert matching the filters, newest first. No paging - see below."""
    alerts = _read(ALERTS_FILE, [])
    if severity:
        alerts = [a for a in alerts if a.get("severity") == severity]
    if unread_only:
        alerts = [a for a in alerts if not a.get("read")]
    if rule:
        alerts = [a for a in alerts if a.get("rule") == rule]
    if query:
        needle = query.lower()
        alerts = [
            a for a in alerts
            if needle in " ".join(
                str(a.get(k) or "") for k in ("title", "message", "device_name", "rule")
            ).lower()
            or needle in str((a.get("extra") or {}).get("ip") or "").lower()
        ]
    return alerts


def load_alerts(limit: int | None = None, severity: str | None = None, unread_only: bool = False,
                rule: str | None = None, query: str | None = None, offset: int = 0) -> list[dict]:
    alerts = filter_alerts(severity, unread_only, rule, query)[offset:]
    return alerts[:limit] if limit else alerts


def add_alerts(new: list[dict]) -> int:
    if not new:
        return 0
    with _lock:
        alerts = _read(ALERTS_FILE, [])
        _write(ALERTS_FILE, (new + alerts)[:MAX_ALERTS])
    return len(new)


def mark_read(timestamps: list[str] | None = None) -> int:
    """Mark the given alerts read; with no argument, mark everything read."""
    with _lock:
        alerts = _read(ALERTS_FILE, [])
        n = 0
        for a in alerts:
            if (timestamps is None or a.get("timestamp") in timestamps) and not a.get("read"):
                a["read"] = True
                n += 1
        _write(ALERTS_FILE, alerts)
    return n


def clear_alerts() -> None:
    with _lock:
        _write(ALERTS_FILE, [])


def summary() -> dict:
    alerts = _read(ALERTS_FILE, [])
    counts = {"info": 0, "warning": 0, "critical": 0}
    for a in alerts:
        counts[a.get("severity", "info")] = counts.get(a.get("severity", "info"), 0) + 1
    return {
        "total": len(alerts),
        "unread": sum(1 for a in alerts if not a.get("read")),
        "by_severity": counts,
        "latest": alerts[0] if alerts else None,
    }


def load_state() -> dict:
    return _read(STATE_FILE, {"snapshot": {}, "miss_counts": {}, "last_run": None})


def save_state(state: dict) -> None:
    with _lock:
        _write(STATE_FILE, state)
