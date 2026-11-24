"""/api/insights - Network Insights (passive). See analysis/insights.py."""

from __future__ import annotations

import threading
import time

from flask import Blueprint, jsonify, request

from mynes.analysis import insights
from mynes.core.network import get_default_gateway


def create_insights_api(scanner) -> Blueprint:
    bp = Blueprint("insights_api", __name__, url_prefix="/api/insights")
    cache = {"at": 0.0, "report": None}
    lock = threading.Lock()

    def _dhcp():
        try:
            from mynes.discovery import dhcp
            return dhcp, dhcp.server_info(), dhcp.chatter()
        except Exception:  # noqa: BLE001
            return None, {}, {}

    @bp.get("/network")
    def network():
        """Internet/DNS/path report; cached 5 min (traceroute takes seconds)."""
        fresh = request.args.get("refresh") in ("1", "true")
        with lock:
            if fresh or not cache["report"] or time.time() - cache["at"] > 300:
                _, server, _ = _dhcp()
                cache["report"] = insights.internet_report(get_default_gateway(), server)
                cache["at"] = time.time()
            return jsonify(cache["report"])

    @bp.get("/devices")
    def devices():
        mod, _server, chatter = _dhcp()
        listening = bool(mod and mod._listener and mod._listener.thread and mod._listener.thread.is_alive())
        rows = []
        for d in scanner.get_devices():
            ip = str(d.get("ip") or "")
            # Radio-only (BLE) entries have no IP traffic to speak of, and
            # Docker/virtual nodes live on this host.
            if not ip or d.get("virtual") or d.get("device_type") in ("Docker Network", "Docker Container"):
                continue
            rows.append(insights.device_summary(d, chatter))
        rows.sort(key=lambda r: (r["status"] != "online", -sum(b["count"] for b in r["broadcasts"].values()),
                                 str(r["name"]).lower()))
        return jsonify({"listener": listening, "devices": rows,
                        "dns_source": {"per_device": False, "plan": "docs/plans/adguard-home-rpifx.md"}})

    return bp
