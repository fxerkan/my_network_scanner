"""REST API for the features added in v2: discovery, monitoring, integrations.

Kept in a blueprint rather than bolted onto app.py, which is already 2k lines.
This is also the API surface the Phase-2 mobile app talks to, so responses are
plain JSON with no template coupling.
"""

from __future__ import annotations

import logging

from flask import Blueprint, jsonify, request

from mynes.discovery import discover_all
from mynes.integrations.home_assistant import HomeAssistantClient, publish_devices
from mynes.monitoring import notify, store
from mynes.monitoring.scheduler import MonitorScheduler
from mynes.platform import privileges, service

log = logging.getLogger(__name__)


def create_api(scanner, config_manager) -> tuple[Blueprint, MonitorScheduler]:
    bp = Blueprint("api_v2", __name__, url_prefix="/api")
    monitor = MonitorScheduler(scanner, config_manager)

    def _devices():
        devices = scanner.get_devices()
        return list(devices.values()) if isinstance(devices, dict) else (devices or [])

    # -- discovery --------------------------------------------------------
    @bp.get("/discovery")
    def run_discovery():
        """Multi-protocol sweep: mDNS/Matter, SSDP/UPnP, MQTT/Zigbee, BLE."""
        timeout = min(float(request.args.get("timeout", 8)), 60)
        protocols = request.args.get("protocols")
        enabled = [p.strip() for p in protocols.split(",")] if protocols else None
        return jsonify(discover_all(timeout=timeout, enabled=enabled))

    @bp.post("/discovery/apply")
    def apply_discovery():
        """Fold sweep results into the saved device list.

        A sweep on its own is ephemeral - this is what makes it stick. Only
        empty fields are filled: a name the user set by hand always wins.
        Discovery-only devices (BLE, Zigbee) have no IP and no ARP entry, so
        they are reported as unmatched rather than invented as devices.
        """
        body = request.get_json(silent=True) or {}
        found = body.get("devices")
        if found is None:
            found = discover_all(timeout=min(float(body.get("timeout", 8)), 60))["devices"]
        return jsonify(_apply_discovery(scanner, found))

    @bp.get("/discovery/protocols")
    def discovery_protocols():
        from mynes.discovery import backends

        rows = []
        for b in backends():
            ok, reason = b.available()
            rows.append({"name": b.name, "available": ok, "detail": reason})
        return jsonify({"protocols": rows})

    # -- monitoring -------------------------------------------------------
    @bp.get("/monitoring/status")
    def monitoring_status():
        return jsonify(monitor.status())

    @bp.get("/monitoring/settings")
    def monitoring_get_settings():
        return jsonify(monitor.settings())

    @bp.post("/monitoring/settings")
    def monitoring_set_settings():
        return jsonify(monitor.update_settings(request.get_json(silent=True) or {}))

    @bp.post("/monitoring/run")
    def monitoring_run_now():
        """Run one scan+diff cycle synchronously and return its summary."""
        try:
            return jsonify(monitor.run_once())
        except Exception as e:  # noqa: BLE001
            log.exception("manual monitoring run failed")
            return jsonify({"error": f"{type(e).__name__}: {e}"}), 500

    # -- alerts -----------------------------------------------------------
    @bp.get("/alerts")
    def list_alerts():
        return jsonify(
            {
                "alerts": store.load_alerts(
                    limit=int(request.args.get("limit", 100)),
                    severity=request.args.get("severity"),
                    unread_only=request.args.get("unread") == "true",
                ),
                "summary": store.summary(),
            }
        )

    @bp.post("/alerts/read")
    def read_alerts():
        body = request.get_json(silent=True) or {}
        return jsonify({"marked": store.mark_read(body.get("timestamps"))})

    @bp.delete("/alerts")
    def clear_alerts():
        store.clear_alerts()
        return jsonify({"cleared": True})

    # -- notifications ----------------------------------------------------
    @bp.post("/notifications/test")
    def test_notification():
        cfg = request.get_json(silent=True) or {}
        if not cfg.get("type"):
            return jsonify({"ok": False, "error": "channel 'type' is required"}), 400
        return jsonify(notify.test_channel(cfg))

    @bp.get("/notifications/channels")
    def notification_channels():
        return jsonify({"types": sorted(notify.SENDERS), "configured": monitor.settings()["notify_channels"]})

    # -- Home Assistant ---------------------------------------------------
    @bp.get("/integrations/home-assistant")
    def ha_status():
        client = HomeAssistantClient()
        return jsonify({"configured": client.configured(), "url": client.url or None, **client.ping()})

    @bp.get("/integrations/home-assistant/devices")
    def ha_devices():
        client = HomeAssistantClient()
        if not client.configured():
            return jsonify({"error": "set MYNES_HA_URL and MYNES_HA_TOKEN"}), 400
        try:
            return jsonify({"devices": client.devices()})
        except Exception as e:  # noqa: BLE001
            return jsonify({"error": f"{type(e).__name__}: {e}"}), 502

    @bp.get("/integrations/home-assistant/compare")
    def ha_compare():
        client = HomeAssistantClient()
        if not client.configured():
            return jsonify({"error": "set MYNES_HA_URL and MYNES_HA_TOKEN"}), 400
        try:
            return jsonify(client.compare(_devices()))
        except Exception as e:  # noqa: BLE001
            return jsonify({"error": f"{type(e).__name__}: {e}"}), 502

    @bp.post("/integrations/mqtt/publish")
    def mqtt_publish():
        """Push all devices to Home Assistant via MQTT discovery."""
        body = request.get_json(silent=True) or {}
        try:
            result = publish_devices(_devices(), store.load_alerts(limit=50), broker=body.get("broker"))
            return jsonify(result), (200 if result.get("ok") else 400)
        except Exception as e:  # noqa: BLE001
            return jsonify({"ok": False, "error": f"{type(e).__name__}: {e}"}), 502

    # -- health -----------------------------------------------------------
    @bp.get("/health")
    def health():
        """Liveness probe for Docker/k8s and the mobile app's connection check."""
        return jsonify(
            {
                "status": "ok",
                "devices": len(_devices()),
                "monitoring": monitor.status()["running"],
                "alerts": store.summary(),
                "scan_method": getattr(scanner, "last_arp_method", None),
                "privilege_hint": getattr(scanner, "privilege_hint", None),
            }
        )

    @bp.get("/capabilities")
    def capabilities():
        """What this install can actually do - drives the UI's warnings.

        The common support question is "why does it only find two devices?",
        which is almost always missing raw-socket privileges or a missing nmap.
        Answer it in the product instead of in an issue thread.
        """
        import shutil

        from mynes.core.arp import has_raw_socket_privilege
        from mynes.discovery import backends

        elevated = has_raw_socket_privilege()
        return jsonify(
            {
                "raw_sockets": {
                    "available": elevated,
                    "detail": "full layer-2 ARP scan"
                    if elevated
                    else "falling back to ping sweep + OS ARP cache; run elevated "
                         "(sudo / Administrator, or Docker with NET_RAW) to find "
                         "devices that ignore ICMP",
                },
                "nmap": {
                    "available": bool(shutil.which("nmap")),
                    "detail": "port and service detection"
                    if shutil.which("nmap")
                    else "nmap is not installed - port scanning is skipped",
                },
                "protocols": [
                    {"name": b.name, "available": b.available()[0], "detail": b.available()[1]}
                    for b in backends()
                ],
                "privileges": privileges.plan().to_dict(),
                "service": service.status(),
                "tray": {"available": _tray_available()},
            }
        )

    # -- platform integration ---------------------------------------------
    @bp.post("/platform/privileges/apply")
    def apply_privileges():
        """Run the platform's privilege fix.

        Deliberately opt-in: the UI shows the exact commands first, and the OS
        password prompt appears in the terminal MyNeS was started from - a web
        page must never be able to silently escalate.
        """
        body = request.get_json(silent=True) or {}
        return jsonify(privileges.apply(dry_run=bool(body.get("dry_run"))))

    @bp.get("/platform/service")
    def service_status():
        return jsonify(service.status())

    @bp.post("/platform/service/<action>")
    def service_action(action):
        if action not in ("install", "uninstall"):
            return jsonify({"ok": False, "detail": "action must be install or uninstall"}), 400
        return jsonify(service.install() if action == "install" else service.uninstall())

    return bp, monitor


def _apply_discovery(scanner, found: list[dict]) -> dict:
    """Merge discovery rows into scanner.devices. Pure enough to test directly."""
    devices = scanner.get_devices()
    devices = list(devices.values()) if isinstance(devices, dict) else (devices or [])
    by_ip = {d.get("ip"): d for d in devices if d.get("ip")}
    by_mac = {d.get("mac", "").lower(): d for d in devices if d.get("mac")}

    updated, unmatched = 0, []
    for row in found:
        target = by_mac.get((row.get("mac") or "").lower()) or by_ip.get(row.get("ip"))
        if target is None:
            unmatched.append({k: row.get(k) for k in ("name", "ip", "mac", "sources")})
            continue

        changed = False
        for src, dst in (("name", "hostname"), ("vendor", "vendor"), ("device_type", "device_type")):
            if row.get(src) and not target.get(dst):
                target[dst] = row[src]
                changed = True

        # Everything the protocols saw, kept verbatim for the device detail page.
        previous = target.get("discovery") or {}
        merged = {
            "sources": sorted(set(previous.get("sources", [])) | set(row.get("sources", []))),
            "services": sorted(set(previous.get("services", [])) | set(row.get("services", []))),
            "attributes": {**previous.get("attributes", {}), **row.get("attributes", {})},
            "model": row.get("model") or previous.get("model"),
        }
        if merged != previous:
            target["discovery"] = merged
            changed = True
        updated += changed

    if updated:
        scanner.save_devices()
    return {"updated": updated, "matched": len(found) - len(unmatched), "unmatched": unmatched}


def _tray_available() -> bool:
    import importlib.util

    return all(importlib.util.find_spec(m) is not None for m in ("pystray", "PIL"))
