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
            }
        )

    return bp, monitor
