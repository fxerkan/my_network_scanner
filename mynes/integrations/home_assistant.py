"""Home Assistant integration - two directions.

**Push (MQTT Discovery)**: every device MyNeS finds becomes a Home Assistant
entity automatically, with no YAML. Each device publishes a `device_tracker`
(home/not_home) plus diagnostic sensors, and MyNeS itself publishes summary
sensors (device count, alert count, last scan). Configs are retained, so HA
picks them up whenever it restarts.

**Pull (REST API)**: read HA's own device/entity registry so MyNeS can show what
HA already knows - Zigbee, Z-Wave, Matter, Bluetooth and cloud devices that no
IP scan can see - and diff it against what MyNeS found.

Both halves are optional; neither is required for MyNeS to run.
"""

from __future__ import annotations

import json
import logging
import os
import re
import urllib.error
import urllib.request

log = logging.getLogger(__name__)

DISCOVERY_PREFIX = os.environ.get("MYNES_HA_DISCOVERY_PREFIX", "homeassistant")
STATE_PREFIX = "mynes"
ORIGIN = {"name": "MyNeS", "sw_version": "2.0.0", "support_url": "https://github.com/fxerkan/my_network_scanner"}

_SLUG = re.compile(r"[^a-z0-9_]+")


def slugify(value: str) -> str:
    return _SLUG.sub("_", str(value or "unknown").lower()).strip("_") or "unknown"


def _object_id(device: dict) -> str:
    return slugify(device.get("mac") or device.get("ip") or device.get("hostname") or "device")


def _device_block(device: dict) -> dict:
    """The HA `device` block - this is what groups entities into one device card."""
    name = device.get("alias") or device.get("hostname") or device.get("ip") or "Unknown device"
    block = {
        "identifiers": [f"mynes_{_object_id(device)}"],
        "name": name,
        "manufacturer": device.get("vendor") or "Unknown",
        "model": device.get("model") or device.get("device_type") or "Network device",
        "via_device": "mynes_scanner",
    }
    connections = []
    if device.get("mac"):
        connections.append(["mac", device["mac"].lower()])
    if connections:
        block["connections"] = connections
    return block


def _is_online(device: dict) -> bool:
    return str(device.get("status", "")).lower() in ("online", "up", "active") or bool(device.get("is_online"))


def build_discovery_payloads(device: dict) -> list[tuple[str, dict]]:
    """Return [(config_topic, payload)] for one device."""
    oid = _object_id(device)
    dev_block = _device_block(device)
    state_topic = f"{STATE_PREFIX}/device/{oid}/state"
    payloads = [
        (
            f"{DISCOVERY_PREFIX}/device_tracker/mynes/{oid}/config",
            {
                "name": None,  # inherit the device name
                "unique_id": f"mynes_{oid}_tracker",
                "state_topic": state_topic,
                "value_template": "{{ value_json.state }}",
                "json_attributes_topic": state_topic,
                "json_attributes_template": "{{ value_json.attributes | tojson }}",
                "payload_home": "home",
                "payload_not_home": "not_home",
                "source_type": "router",
                "device": dev_block,
                "origin": ORIGIN,
            },
        )
    ]

    diagnostics = [
        ("ip", "IP address", None, None, "mdi:ip-network"),
        ("vendor", "Vendor", None, None, "mdi:factory"),
        ("device_type", "Device type", None, None, "mdi:devices"),
        ("open_port_count", "Open ports", None, None, "mdi:lan-connect"),
        ("response_time", "Response time", "duration", "ms", "mdi:timer-outline"),
    ]
    for key, label, dev_class, unit, icon in diagnostics:
        cfg = {
            "name": label,
            "unique_id": f"mynes_{oid}_{key}",
            "state_topic": state_topic,
            "value_template": f"{{{{ value_json.{key} }}}}",
            "entity_category": "diagnostic",
            "icon": icon,
            "device": dev_block,
            "origin": ORIGIN,
        }
        if dev_class:
            cfg["device_class"] = dev_class
        if unit:
            cfg["unit_of_measurement"] = unit
        payloads.append((f"{DISCOVERY_PREFIX}/sensor/mynes/{oid}_{key}/config", cfg))

    return payloads


def build_state(device: dict) -> dict:
    ports = device.get("open_ports") or device.get("ports") or []
    return {
        "state": "home" if _is_online(device) else "not_home",
        "ip": device.get("ip"),
        "vendor": device.get("vendor") or "Unknown",
        "device_type": device.get("device_type") or "Unknown",
        "open_port_count": len(ports),
        "response_time": device.get("response_time"),
        "attributes": {
            "mac": device.get("mac"),
            "hostname": device.get("hostname"),
            "alias": device.get("alias"),
            "last_seen": device.get("last_seen"),
            "open_ports": ports,
            "services": device.get("services") or [],
            "discovery_sources": device.get("discovery_sources") or [],
        },
    }


def build_scanner_payloads(devices: list, alerts: list) -> list[tuple[str, dict, bool]]:
    """Summary sensors for MyNeS itself. Returns [(topic, payload, retain)]."""
    online = sum(1 for d in devices if isinstance(d, dict) and _is_online(d))
    critical = sum(1 for a in alerts if a.get("severity") == "critical")
    scanner_block = {
        "identifiers": ["mynes_scanner"],
        "name": "MyNeS Network Scanner",
        "manufacturer": "fxerkan",
        "model": "MyNeS",
        "sw_version": ORIGIN["sw_version"],
    }
    state_topic = f"{STATE_PREFIX}/scanner/state"

    out = []
    sensors = [
        ("devices_total", "Devices total", "mdi:lan", None),
        ("devices_online", "Devices online", "mdi:lan-connect", None),
        ("alerts_total", "Alerts", "mdi:bell-alert", None),
        ("alerts_critical", "Critical alerts", "mdi:alert-octagon", None),
    ]
    for key, label, icon, unit in sensors:
        cfg = {
            "name": label,
            "unique_id": f"mynes_scanner_{key}",
            "state_topic": state_topic,
            "value_template": f"{{{{ value_json.{key} }}}}",
            "state_class": "measurement",
            "icon": icon,
            "device": scanner_block,
            "origin": ORIGIN,
        }
        if unit:
            cfg["unit_of_measurement"] = unit
        out.append((f"{DISCOVERY_PREFIX}/sensor/mynes/scanner_{key}/config", cfg, True))

    out.append(
        (
            state_topic,
            {
                "devices_total": len(devices),
                "devices_online": online,
                "alerts_total": len(alerts),
                "alerts_critical": critical,
            },
            True,
        )
    )
    return out


def publish_devices(devices: list, alerts: list | None = None, broker: dict | None = None) -> dict:
    """Publish HA MQTT discovery configs + states. Returns a small summary."""
    import paho.mqtt.client as mqtt

    broker = broker or {}
    host = broker.get("host") or os.environ.get("MYNES_MQTT_HOST")
    if not host:
        return {"ok": False, "error": "no MQTT broker configured (set MYNES_MQTT_HOST)"}

    client = mqtt.Client(client_id="mynes-publisher")
    username = broker.get("username") or os.environ.get("MYNES_MQTT_USERNAME")
    if username:
        client.username_pw_set(username, broker.get("password") or os.environ.get("MYNES_MQTT_PASSWORD"))

    client.connect(host, int(broker.get("port") or os.environ.get("MYNES_MQTT_PORT") or 1883), keepalive=30)
    client.loop_start()
    published = 0
    try:
        for topic, payload, retain in build_scanner_payloads(devices, alerts or []):
            client.publish(topic, json.dumps(payload), qos=1, retain=retain)
            published += 1

        for device in devices:
            if not isinstance(device, dict) or not (device.get("mac") or device.get("ip")):
                continue
            for topic, payload in build_discovery_payloads(device):
                client.publish(topic, json.dumps(payload), qos=1, retain=True)
                published += 1
            client.publish(
                f"{STATE_PREFIX}/device/{_object_id(device)}/state",
                json.dumps(build_state(device), default=str),
                qos=1,
                retain=True,
            )
            published += 1
    finally:
        client.loop_stop()
        client.disconnect()

    return {"ok": True, "published": published, "devices": len(devices), "broker": host}


# ---------------------------------------------------------------------------
# Pull side: read what Home Assistant already knows.
# ---------------------------------------------------------------------------


class HomeAssistantClient:
    """Minimal HA REST client. Needs a Long-Lived Access Token.

    Create one in HA: profile page -> Security -> Long-lived access tokens.
    """

    def __init__(self, url: str | None = None, token: str | None = None, timeout: int = 15):
        self.url = (url or os.environ.get("MYNES_HA_URL") or "").rstrip("/")
        self.token = token or os.environ.get("MYNES_HA_TOKEN")
        self.timeout = timeout

    def configured(self) -> bool:
        return bool(self.url and self.token)

    def _get(self, path: str):
        req = urllib.request.Request(
            f"{self.url}{path}",
            headers={"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
            return json.loads(resp.read().decode("utf-8"))

    def ping(self) -> dict:
        if not self.configured():
            return {"ok": False, "error": "MYNES_HA_URL and MYNES_HA_TOKEN are required"}
        try:
            return {"ok": True, **self._get("/api/config")}
        except urllib.error.HTTPError as e:
            return {"ok": False, "error": f"HTTP {e.code} - {'bad token' if e.code == 401 else e.reason}"}
        except (urllib.error.URLError, OSError, ValueError) as e:
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}

    def states(self) -> list[dict]:
        return self._get("/api/states")

    def devices(self) -> list[dict]:
        """HA entities condensed into device-ish rows, keyed by MAC/IP when known.

        The device registry is only exposed over the WebSocket API, so we derive
        what we can from `/api/states`, which the REST token can read.
        """
        out = []
        for state in self.states():
            attrs = state.get("attributes") or {}
            domain = state["entity_id"].split(".")[0]
            if domain not in ("device_tracker", "sensor", "binary_sensor", "light", "switch", "climate", "media_player"):
                continue
            mac = attrs.get("mac") or attrs.get("mac_address")
            ip = attrs.get("ip") or attrs.get("ip_address")
            if domain != "device_tracker" and not (mac or ip):
                continue
            out.append(
                {
                    "entity_id": state["entity_id"],
                    "domain": domain,
                    "name": attrs.get("friendly_name") or state["entity_id"],
                    "state": state.get("state"),
                    "mac": mac,
                    "ip": ip,
                    "source_type": attrs.get("source_type"),
                    "device_class": attrs.get("device_class"),
                    "manufacturer": attrs.get("manufacturer"),
                    "model": attrs.get("model"),
                    "attributes": attrs,
                }
            )
        return out

    def compare(self, mynes_devices: list[dict]) -> dict:
        """Diff HA's view against MyNeS's view."""
        ha = self.devices()

        def norm(v):
            return str(v).lower().replace("-", ":") if v else None

        ha_macs = {norm(d["mac"]) for d in ha if d.get("mac")}
        ha_ips = {d["ip"] for d in ha if d.get("ip")}
        my_macs = {norm(d.get("mac")) for d in mynes_devices if d.get("mac")}
        my_ips = {d.get("ip") for d in mynes_devices if d.get("ip")}

        only_ha = [d for d in ha if norm(d.get("mac")) not in my_macs and d.get("ip") not in my_ips]
        only_mynes = [
            d for d in mynes_devices if norm(d.get("mac")) not in ha_macs and d.get("ip") not in ha_ips
        ]

        return {
            "home_assistant_total": len(ha),
            "mynes_total": len(mynes_devices),
            "in_both": len((my_macs & ha_macs) | (my_ips & ha_ips)),
            "only_in_home_assistant": only_ha,
            "only_in_mynes": only_mynes,
            "by_source_type": _count(ha, "source_type"),
            "by_domain": _count(ha, "domain"),
        }


def _count(rows, key):
    out = {}
    for r in rows:
        out[r.get(key) or "unknown"] = out.get(r.get(key) or "unknown", 0) + 1
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))


def demo():
    """Self-check for payload construction - no broker, no HA needed."""
    dev = {"mac": "AA:BB:CC:11:22:33", "ip": "192.168.1.50", "alias": "Pi", "status": "online", "open_ports": [22, 80]}
    payloads = build_discovery_payloads(dev)
    topics = [t for t, _ in payloads]
    assert any("device_tracker/mynes/aa_bb_cc_11_22_33/config" in t for t in topics), topics
    assert all(p["device"]["identifiers"] == ["mynes_aa_bb_cc_11_22_33"] for _, p in payloads)
    assert len({p["unique_id"] for _, p in payloads}) == len(payloads), "unique_ids must not collide"

    state = build_state(dev)
    assert state["state"] == "home" and state["open_port_count"] == 2
    assert build_state({**dev, "status": "offline"})["state"] == "not_home"

    scanner = build_scanner_payloads([dev], [{"severity": "critical"}])
    assert any(p.get("alerts_critical") == 1 for _, p, _ in scanner)
    print("home_assistant demo OK")


if __name__ == "__main__":
    demo()
