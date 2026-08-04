"""Periodic scanning: scan -> diff -> alert -> notify -> publish.

One daemon thread with a sleep loop. No APScheduler, no cron, no extra process.

ponytail: a single background thread is enough for one network on one box.
If MyNeS ever needs multiple independent schedules, move to APScheduler.
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone

from mynes.monitoring import notify, rules, store

log = logging.getLogger(__name__)

DEFAULTS = {
    "enabled": False,
    "interval_minutes": 30,
    "include_offline": True,
    "run_discovery": True,
    "discovery_timeout": 6,
    "notify_channels": [],
    "enabled_rules": None,  # None = all rules
    "thresholds": {},
    "publish_to_mqtt": False,
}


def _snapshot(devices) -> dict[str, dict]:
    """Normalise the scanner's output into {identity: device} for the rules."""
    if isinstance(devices, dict):
        devices = list(devices.values())
    snap = {}
    for d in devices or []:
        if not isinstance(d, dict):
            continue
        key = (d.get("mac") or d.get("ip") or "").lower()
        if key:
            snap[key] = d
    return snap


class MonitorScheduler:
    """Runs scans on a timer and turns the differences into notifications."""

    def __init__(self, scanner, config_manager=None):
        self.scanner = scanner
        self.config_manager = config_manager
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._lock = threading.Lock()
        self.last_run: str | None = None
        self.last_result: dict | None = None
        self.last_error: str | None = None

    # -- config -----------------------------------------------------------
    def settings(self) -> dict:
        cfg = {}
        if self.config_manager is not None:
            try:
                cfg = (self.config_manager.config or {}).get("monitoring", {}) or {}
            except Exception as e:  # noqa: BLE001
                log.warning("could not read monitoring config: %s", e)
        return {**DEFAULTS, **cfg}

    def update_settings(self, patch: dict) -> dict:
        """Merge a settings patch into config.json and apply it to the loop."""
        merged = {**self.settings(), **(patch or {})}
        merged.pop("_note", None)
        if self.config_manager is not None:
            self.config_manager.config["monitoring"] = merged
            self.config_manager.save_config()
        if merged["enabled"]:
            self.start()
        else:
            self.stop()
        self._wake.set()  # pick up the new interval without waiting out the old one
        return merged

    def status(self) -> dict:
        s = self.settings()
        state = store.load_state()
        baseline = state.get("snapshot") or {}
        return {
            "running": bool(self._thread and self._thread.is_alive()),
            "enabled": s["enabled"],
            "interval_minutes": s["interval_minutes"],
            # Survives a restart: last_run lives in the state file, not just memory.
            "last_run": self.last_run or state.get("last_run"),
            "last_error": self.last_error,
            "last_result": self.last_result,
            "has_baseline": bool(baseline),
            "baseline_devices": len(baseline),
            "next_run_in_seconds": self._seconds_until_next(s),
            "channels": [
                {"type": c.get("type"), "name": c.get("name"), "enabled": c.get("enabled", True)}
                for c in s["notify_channels"]
            ],
            "alerts": store.summary(),
        }

    def _seconds_until_next(self, settings) -> int | None:
        last = self.last_run or store.load_state().get("last_run")
        if not (self._thread and self._thread.is_alive() and last):
            return None
        try:
            elapsed = (datetime.now(timezone.utc) - datetime.fromisoformat(last)).total_seconds()
        except (TypeError, ValueError):
            return None
        return max(0, int(settings["interval_minutes"] * 60 - elapsed))

    # -- lifecycle --------------------------------------------------------
    def start(self) -> bool:
        with self._lock:
            if self._thread and self._thread.is_alive():
                return False
            self._stop.clear()
            self._thread = threading.Thread(target=self._loop, name="mynes-monitor", daemon=True)
            self._thread.start()
            log.info("monitor scheduler started (every %s min)", self.settings()["interval_minutes"])
            return True

    def stop(self) -> bool:
        with self._lock:
            if not (self._thread and self._thread.is_alive()):
                return False
            self._stop.set()
            self._wake.set()
            self._thread.join(timeout=10)
            self._thread = None
            return True

    def trigger_now(self) -> None:
        """Ask the loop to run immediately instead of waiting out the interval."""
        self._wake.set()

    def _loop(self):
        while not self._stop.is_set():
            settings = self.settings()
            if settings["enabled"]:
                try:
                    self.run_once(settings)
                    self.last_error = None
                except Exception as e:  # noqa: BLE001 - the loop must survive anything
                    self.last_error = f"{type(e).__name__}: {e}"
                    log.exception("scheduled scan failed")

            self._wake.wait(timeout=max(60, settings["interval_minutes"] * 60))
            self._wake.clear()

    # -- the actual work --------------------------------------------------
    def run_once(self, settings: dict | None = None) -> dict:
        """Scan, diff against the last snapshot, alert, notify. Returns a summary."""
        settings = settings or self.settings()
        started = time.monotonic()

        self.scanner.scan_network(include_offline=settings["include_offline"])
        devices = self.scanner.get_devices()

        if settings["run_discovery"]:
            devices = self._enrich_with_discovery(devices, settings["discovery_timeout"])

        state = store.load_state()
        previous = state.get("snapshot") or {}
        is_baseline = not previous
        current = _snapshot(devices)
        alerts, misses = rules.evaluate(
            previous=previous,
            current=current,
            miss_counts=state.get("miss_counts") or {},
            thresholds=settings["thresholds"],
            enabled_rules=settings["enabled_rules"],
        )

        alert_dicts = [a.to_dict() for a in alerts]
        store.add_alerts(alert_dicts)
        self.last_run = datetime.now(timezone.utc).isoformat()
        store.save_state({"snapshot": current, "miss_counts": misses, "last_run": self.last_run})

        deliveries = notify.dispatch(settings["notify_channels"], alert_dicts)

        if settings["publish_to_mqtt"]:
            self._publish(devices, alert_dicts)

        self.last_result = {
            "at": self.last_run,
            "duration_seconds": round(time.monotonic() - started, 1),
            "devices": len(current),
            "alerts": len(alert_dicts),
            "baseline": is_baseline,
            "message": (
                f"Baseline recorded for {len(current)} devices. "
                "Changes from here on will be reported."
                if is_baseline
                else f"{len(current)} devices, {len(alert_dicts)} alerts."
            ),
            "by_severity": {s: sum(1 for a in alert_dicts if a["severity"] == s) for s in rules.SEVERITIES},
            "deliveries": deliveries,
        }
        log.info("scheduled scan: %s devices, %s alerts%s",
                 len(current), len(alert_dicts), " (baseline)" if is_baseline else "")
        return self.last_result

    def _enrich_with_discovery(self, devices, timeout):
        """Fold mDNS/SSDP/BLE/MQTT results into the IP-scan device list."""
        try:
            from mynes.discovery import discover_all
        except ImportError:
            return devices

        found = discover_all(timeout=timeout).get("devices", [])
        by_ip = {d.get("ip"): d for d in devices if isinstance(d, dict) and d.get("ip")}

        for extra in found:
            target = by_ip.get(extra.get("ip"))
            if target is None:
                # Radio-only device (BLE/Zigbee) - no IP, so it joins as its own entry.
                devices.append(
                    {
                        "ip": extra.get("ip"),
                        "mac": extra.get("mac"),
                        "hostname": extra.get("name"),
                        "alias": extra.get("name"),
                        "vendor": extra.get("vendor"),
                        "device_type": extra.get("device_type"),
                        "status": "online",
                        "discovery_sources": extra.get("sources", []),
                        "services": extra.get("services", []),
                        "attributes": extra.get("attributes", {}),
                    }
                )
                continue

            target.setdefault("discovery_sources", [])
            for src in extra.get("sources", []):
                if src not in target["discovery_sources"]:
                    target["discovery_sources"].append(src)
            target["services"] = sorted(set(target.get("services") or []) | set(extra.get("services") or []))
            target.setdefault("attributes", {}).update(extra.get("attributes") or {})
            for field in ("vendor", "model", "device_type"):
                target[field] = target.get(field) or extra.get(field)
        return devices

    def _publish(self, devices, alerts):
        try:
            from mynes.integrations.home_assistant import publish_devices

            publish_devices(devices, alerts)
        except Exception as e:  # noqa: BLE001
            log.warning("MQTT publish failed: %s", e)
