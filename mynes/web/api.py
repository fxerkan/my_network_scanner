"""REST API for the features added in v2: discovery, monitoring, integrations.

Kept in a blueprint rather than bolted onto app.py, which is already 2k lines.
This is also the API surface the Phase-2 mobile app talks to, so responses are
plain JSON with no template coupling.
"""

from __future__ import annotations

import logging

from flask import Blueprint, jsonify, request

from mynes.core import topology
from mynes.core.network import get_default_gateway
from mynes.discovery import discover_all
from mynes.integrations.home_assistant import HomeAssistantClient, publish_devices
from mynes.monitoring import notify, push, store, uptime
from mynes.monitoring.scheduler import MonitorScheduler
from mynes.platform import privileges, service

log = logging.getLogger(__name__)


def create_api(scanner, config_manager) -> tuple[Blueprint, MonitorScheduler]:
    bp = Blueprint("api_v2", __name__, url_prefix="/api")
    monitor = MonitorScheduler(scanner, config_manager)

    # Scheduled scanning is a persisted setting, so it has to survive a restart.
    # Without this the schedule silently stopped every time the app came back up
    # and the UI showed "enabled" next to "not running".
    if monitor.settings()["enabled"]:
        monitor.start()
        log.info("monitoring enabled in config - scheduler started")

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

    @bp.get("/monitoring/uptime")
    def monitoring_uptime():
        """Per-device up/warn/down history, one cell per scheduled scan."""
        limit = max(1, min(int(request.args.get("limit", 48)), uptime.CAP))
        return jsonify({**uptime.series(limit), "enabled": monitor.settings()["enabled"]})

    # -- alerts -----------------------------------------------------------
    @bp.get("/alerts")
    def list_alerts():
        severity = request.args.get("severity")
        rule = request.args.get("rule")
        query = request.args.get("q")
        unread_only = request.args.get("unread") == "true"
        limit = max(1, min(int(request.args.get("limit", 100)), 500))
        offset = max(0, int(request.args.get("offset", 0)))
        # `total` is the filtered count, not the file's: the pager has to know
        # how many pages the *current* filter has, not how many alerts exist.
        matched = store.filter_alerts(severity, unread_only, rule, query)
        return jsonify(
            {
                "alerts": matched[offset:offset + limit],
                "total": len(matched),
                "offset": offset,
                "limit": limit,
                "rules": sorted({a.get("rule") for a in store.load_alerts() if a.get("rule")}),
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

    @bp.get("/integrations/home-assistant/notify-services")
    def ha_notify_services():
        """The notify.* services this HA install exposes, for the channel picker."""
        client = HomeAssistantClient()
        if not client.configured():
            return jsonify({"error": "set MYNES_HA_URL and MYNES_HA_TOKEN"}), 400
        try:
            return jsonify({"services": client.notify_services()})
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

    # -- push (MyNeS's own notifications) ---------------------------------
    @bp.get("/push/key")
    def push_key():
        """The VAPID public key a browser needs before it can subscribe."""
        ok, reason = push.available()
        return jsonify({"available": ok, "detail": reason, "public_key": push.vapid_public_key()})

    @bp.get("/push/subscriptions")
    def push_list():
        # Endpoints are secrets - anyone holding one can push to that device -
        # so the list is summarised rather than echoed back.
        rows = [
            {
                "kind": s.get("kind"),
                "label": s.get("label"),
                "created": s.get("created"),
                "id": (s.get("endpoint") or s.get("token") or "")[-24:],
            }
            for s in push.subscriptions()
        ]
        return jsonify({"subscriptions": rows, "count": len(rows)})

    @bp.post("/push/subscribe")
    def push_subscribe():
        body = request.get_json(silent=True) or {}
        try:
            entry = push.subscribe(body.get("subscription") or body, body.get("label"))
        except ValueError as e:
            return jsonify({"ok": False, "error": str(e)}), 400

        # Registering a device is the whole intent of "enable notifications";
        # making the user *also* add a channel afterwards just means alerts
        # silently go nowhere. Create it once, then leave it alone.
        channels = monitor.settings()["notify_channels"]
        created = not any(c.get("type") == "mynes_push" for c in channels)
        if created:
            monitor.update_settings(
                {
                    "notify_channels": channels
                    + [{"type": "mynes_push", "name": "MyNeS push", "enabled": True, "min_severity": "warning"}]
                }
            )
        return jsonify({"ok": True, "kind": entry["kind"], "label": entry["label"], "channel_created": created})

    @bp.post("/push/unsubscribe")
    def push_unsubscribe():
        body = request.get_json(silent=True) or {}
        key = body.get("endpoint") or body.get("token") or ""
        return jsonify({"ok": push.unsubscribe(key)})

    @bp.post("/push/test")
    def push_test():
        from mynes.monitoring.rules import Alert

        probe = Alert(
            rule="test",
            severity="info",
            title="MyNeS test notification",
            message="If you can read this, push from MyNeS works on this device.",
        ).to_dict()
        return jsonify(push.send(probe))

    # -- topology ---------------------------------------------------------
    @bp.get("/topology")
    def topology_tree():
        """Parent/child tree for the topology view. See core/topology.py for
        why most edges come back as "default" on a flat home LAN."""
        state = topology.load_state()
        return jsonify(
            {
                **topology.build_tree(
                    _devices(), get_default_gateway(),
                    uplinks=state["uplinks"], traced=state["traced"],
                ),
                "uplinks": state["uplinks"],
                "traced": state["traced"],
            }
        )

    @bp.post("/topology/uplinks")
    def topology_set_uplinks():
        """Hand-assign "device X is plugged into Y". The only way to record a
        bridged switch or AP, which is invisible on the wire."""
        body = request.get_json(silent=True) or {}
        state = topology.load_state()
        state["uplinks"] = {**state["uplinks"], **(body.get("uplinks") or {})}
        state["uplinks"] = {k: v for k, v in state["uplinks"].items() if v}
        return jsonify(topology.save_state(state))

    @bp.post("/topology/discover")
    def topology_discover():
        """Traceroute sweep. Slow (seconds per unreachable host) and only ever
        finds routed hops, so it is a button, not part of a scan."""
        devices = _devices()
        traced = topology.discover_uplinks(devices)
        state = topology.load_state()
        state["traced"] = traced
        topology.save_state(state)
        return jsonify({"traced": traced, "checked": len(devices)})

    # -- authentication ---------------------------------------------------
    @bp.get("/auth/status")
    def auth_status():
        from mynes.web import auth

        required = auth.login_required(config_manager)
        username, _ = auth.credentials()
        return jsonify(
            {
                "login_required": required,
                "credentials_configured": auth.credentials_configured(),
                "username": username,
                "active": required and auth.credentials_configured(),
                "source": auth.credentials_source(),
                "hint": (
                    "Set a username and password below, or use MYNES_AUTH_USERNAME "
                    "and MYNES_AUTH_PASSWORD in the environment."
                    if not auth.credentials_configured()
                    else None
                ),
            }
        )

    @bp.post("/auth/credentials")
    def auth_set_credentials():
        """Set the login credentials from the Settings page.

        Editing .env is not an option inside a store-installed container, which
        left the gate permanently unreachable there. Once the gate is on this
        endpoint is behind it like everything else, so it cannot be used to
        take an already-protected install away from its owner.
        """
        from mynes.web import auth

        payload = request.get_json(silent=True) or {}
        if auth.credentials_source() == "env":
            return jsonify({
                "ok": False,
                "error": "Credentials come from the environment. Change "
                         "MYNES_AUTH_USERNAME / MYNES_AUTH_PASSWORD instead.",
            }), 409
        try:
            auth.set_credentials(payload.get("username", ""), payload.get("password", ""))
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        return jsonify({"ok": True, "username": payload.get("username", "").strip(),
                        "source": "stored"})

    @bp.delete("/auth/credentials")
    def auth_clear_credentials():
        from mynes.web import auth

        if auth.credentials_source() == "env":
            return jsonify({"ok": False, "error": "Credentials come from the environment."}), 409
        auth.clear_credentials()
        auth.set_login_required(False)   # never leave the gate on with no way in
        return jsonify({"ok": True, "login_required": False})

    @bp.post("/auth/status")
    def auth_toggle():
        """Turn the login gate on or off.

        Refuses to turn on without credentials — that would lock everyone out
        of a LAN app with no recovery path short of editing JSON on the server.
        """
        from mynes.web import auth

        want = bool((request.get_json(silent=True) or {}).get("login_required"))
        if want and not auth.credentials_configured():
            return jsonify({
                "ok": False,
                "error": "No credentials configured. Set MYNES_AUTH_USERNAME and "
                         "MYNES_AUTH_PASSWORD in .env first, or you would lock yourself out.",
            }), 400

        # Written to data/security.json: config.json is tracked, and whether
        # this install is exposed to the LAN is not a repo default.
        auth.set_login_required(want)
        settings = config_manager.config.get("security_settings")
        if isinstance(settings, dict) and "login_required" in settings:
            settings.pop("login_required", None)      # drop the migrated copy
            config_manager.save_config()
        return jsonify({"ok": True, "login_required": want, "active": want})

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
                "push": {
                    "available": push.available()[0],
                    "detail": push.available()[1],
                    "devices": len(push.subscriptions()),
                },
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
