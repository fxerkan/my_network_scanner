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

    # Both spellings are accepted: the MYNES_-prefixed pair keeps MyNeS settings
    # together in a shared .env, the bare pair is what people type by hand.
    URL_VARS = ("MYNES_HA_URL", "HA_URL")
    TOKEN_VARS = ("MYNES_HA_TOKEN", "HA_TOKEN")

    def __init__(self, url: str | None = None, token: str | None = None, timeout: int = 15):
        self.url = (url or _first_env(self.URL_VARS) or "").rstrip("/")
        self.token = token or _first_env(self.TOKEN_VARS)
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
            # 401/403 from HA both mean the long-lived token is the problem
            # (missing, expired, revoked, or not admin) - say so instead of a bare code.
            hint = "check the Home Assistant token (HA_TOKEN / MYNES_HA_TOKEN - invalid, expired, or revoked)" if e.code in (401, 403) else e.reason
            return {"ok": False, "error": f"HTTP {e.code} - {hint}"}
        except (urllib.error.URLError, OSError, ValueError) as e:
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}

    def notify_services(self) -> list[str]:
        """Every `notify.*` service this install exposes, sorted.

        Used by the notification-channel picker so the user chooses their phone
        from a list instead of guessing `notify.mobile_app_<slug>`.
        """
        domains = self._get("/api/services")
        for entry in domains:
            if entry.get("domain") == "notify":
                return sorted(entry.get("services", {}))
        return []

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

    def device_registry(self) -> list[dict]:
        """HA's real device list, over the WebSocket API.

        `/api/states` only exposes entities, and a Zigbee bulb's state carries no
        MAC or IP - so a REST-only comparison silently misses every radio device,
        which is exactly the set the user cares about. The device registry has
        manufacturer, model, connections and the owning integration, and it is
        WebSocket-only.

        Returns [] (not an error) when websocket-client is not installed, so the
        REST comparison still works.
        """
        try:
            import websocket
        except ImportError:
            return []

        ws_url = self.url.replace("https://", "wss://").replace("http://", "ws://") + "/api/websocket"
        ws = websocket.create_connection(ws_url, timeout=self.timeout)
        try:
            json.loads(ws.recv())  # auth_required
            ws.send(json.dumps({"type": "auth", "access_token": self.token}))
            if json.loads(ws.recv()).get("type") != "auth_ok":
                return []

            def request(msg_id, msg_type):
                ws.send(json.dumps({"id": msg_id, "type": msg_type}))
                while True:
                    msg = json.loads(ws.recv())
                    if msg.get("id") == msg_id and msg.get("type") == "result":
                        return msg.get("result") or [] if msg.get("success") else []

            devices = request(1, "config/device_registry/list")
            entities = request(2, "config/entity_registry/list")
            # Note: `config_entries/get`, NOT `config/config_entries/get` — the
            # latter is an unknown_command and silently yields no integrations,
            # leaving every device's protocol as "unknown".
            entries = request(3, "config_entries/get")
        finally:
            ws.close()

        # config_entry_id -> integration name ("zha", "matter", "zwave_js", ...)
        integration = {e["entry_id"]: e.get("domain") for e in entries if isinstance(e, dict)}
        entity_count: dict[str, int] = {}
        for ent in entities:
            if ent.get("device_id"):
                entity_count[ent["device_id"]] = entity_count.get(ent["device_id"], 0) + 1

        out = []
        for d in devices:
            conns = {c[0]: c[1] for c in (d.get("connections") or []) if len(c) == 2}
            domains = sorted({integration.get(cid) for cid in (d.get("config_entries") or [])} - {None})
            name = d.get("name_by_user") or d.get("name")
            # HA's `generic` integration names devices after their address
            # ("192_168_1_79"), and adapters after their MAC ("hci0 (D8:3A:..)").
            # Both are the only identifier those entries carry, so mine them.
            embedded_ip, embedded_mac = _identifiers_in_name(name)
            out.append(
                {
                    "id": d.get("id"),
                    "name": name,
                    "manufacturer": d.get("manufacturer"),
                    "model": d.get("model"),
                    "mac": conns.get("mac") or embedded_mac,
                    "ip": embedded_ip,
                    "integrations": domains,
                    "protocol": _protocol_for(domains),
                    "entity_count": entity_count.get(d.get("id"), 0),
                    "via_device_id": d.get("via_device_id"),
                    "disabled": bool(d.get("disabled_by")),
                }
            )
        return out

    def compare(self, mynes_devices: list[dict]) -> dict:
        """Diff HA's view against MyNeS's view.

        Uses the device registry when available (it covers Zigbee, Z-Wave,
        Matter and cloud devices) and falls back to entity states otherwise.
        """
        registry = self.device_registry()
        source = "device_registry" if registry else "states"
        all_ha = registry or self.devices()

        # Services, helpers and HACS repositories are registry entries but not
        # devices; diffing them against a network scan produces only noise.
        excluded = [d for d in all_ha if d.get("protocol") == "Not a device"]
        ha = [d for d in all_ha if d.get("protocol") != "Not a device"]

        def norm(v):
            return str(v).lower().replace("-", ":") if v else None

        ha_macs = {norm(d["mac"]) for d in ha if d.get("mac")}
        ha_ips = {d["ip"] for d in ha if d.get("ip")}
        my_macs = {norm(d.get("mac")) for d in mynes_devices if d.get("mac")}
        my_ips = {d.get("ip") for d in mynes_devices if d.get("ip")}

        # HA's device registry rarely carries a MAC and never an IP, so an
        # identifier-only diff under-reports badly. Names are the third signal:
        # "livingroom-pi" in HA is "livingroom-pi.local" here.
        ha_names = {n for d in ha for n in _name_keys(d)}
        my_names = {n for d in mynes_devices for n in _name_keys(d)}

        def matches_ha(d):
            return (
                norm(d.get("mac")) in ha_macs
                or (d.get("ip") and d.get("ip") in ha_ips)
                or bool(_name_keys(d) & ha_names)
            )

        def matches_mynes(d):
            return (
                norm(d.get("mac")) in my_macs
                or (d.get("ip") and d.get("ip") in my_ips)
                or bool(_name_keys(d) & my_names)
            )

        only_ha = [d for d in ha if not matches_mynes(d)]
        only_mynes = [d for d in mynes_devices if not matches_ha(d)]

        return {
            "source": source,
            "home_assistant_total": len(ha),
            "home_assistant_excluded": len(excluded),
            "mynes_total": len(mynes_devices),
            # Count DEVICES that matched, not identifiers - unioning a MAC set
            # with an IP set double-counts anything matching on both and can
            # report more matches than there are devices.
            "in_both": sum(1 for d in mynes_devices if matches_ha(d)),
            "only_in_home_assistant": only_ha,
            "only_in_mynes": only_mynes,
            "by_source_type": _count(ha, "source_type") if source == "states" else _count(ha, "protocol"),
            "by_domain": _count(ha, "domain") if source == "states" else _count(ha, "manufacturer"),
            "by_protocol": _count(ha, "protocol") if source == "device_registry" else {},
        }


# HA integration -> the transport it actually speaks. This is the axis that
# matters for a comparison: it separates "MyNeS could never have seen this"
# (radio, cloud) from "MyNeS should have seen this and did not" (IP).
PROTOCOL_BY_INTEGRATION = {
    # Radio - invisible to any IP scan.
    "zha": "Zigbee", "zigbee2mqtt": "Zigbee", "deconz": "Zigbee", "zigbee": "Zigbee",
    "zwave_js": "Z-Wave", "matter": "Matter", "thread": "Thread", "otbr": "Thread",
    "bluetooth": "Bluetooth", "esphome_ble": "Bluetooth", "xiaomi_ble": "Bluetooth",
    "govee_ble": "Bluetooth", "switchbot": "Bluetooth", "improv_ble": "Bluetooth",
    "led_ble": "Bluetooth", "yalexs_ble": "Bluetooth",
    # On the LAN - MyNeS should find these.
    "esphome": "IP", "shelly": "IP", "tasmota": "IP", "wled": "IP", "hue": "IP",
    "tplink": "IP", "tplink_deco": "IP", "samsungtv": "IP", "androidtv_remote": "IP",
    "androidtv": "IP", "dlna_dmr": "IP", "dlna_dms": "IP", "plex": "IP",
    "jellyfin": "IP", "kodi": "IP", "roku": "IP", "cast": "IP", "yeelight": "IP",
    "philips_airpurifier_coap": "IP", "dyson_local": "IP", "generic": "IP",
    "onvif": "IP", "synology_dsm": "IP", "qnap": "IP", "unifi": "IP",
    "mikrotik": "IP", "asuswrt": "IP", "fritz": "IP", "nut": "IP", "octoprint": "IP",
    "homekit_controller": "IP", "homekit": "IP", "mqtt": "MQTT",
    # Cloud-only - no local footprint at all.
    "tuya": "Cloud", "smartthings": "Cloud", "cloud": "Cloud", "petkit": "Cloud",
    "xiaomi_miot": "Cloud", "fujitsu_airstage": "Cloud", "google_assistant": "Cloud",
    "alexa": "Cloud", "spotify": "Cloud", "withings": "Cloud",
    # A phone running the HA companion app.
    "mobile_app": "Companion app",
}

# Integrations that create registry entries which are not physical devices.
# Comparing a HACS repository entry against a network scan is pure noise, so
# these are reported separately and excluded from the diff.
NON_DEVICE_INTEGRATIONS = {
    "hacs", "sun", "met", "backup", "systemmonitor", "speedtestdotnet",
    "google_generative_ai_conversation", "openai_conversation", "conversation",
    "template", "derivative", "utility_meter", "history_stats", "trend",
    "statistics", "group", "schedule", "todo", "shopping_list", "calendar",
    "workday", "holiday", "uptime", "version", "rpi_power", "hassio",
    "google_translate", "tts", "stt", "wake_word", "assist_pipeline",
    "waze_travel_time", "moon", "season", "worldclock", "time_date",
}


def _protocol_for(domains: list[str]) -> str:
    for d in domains:
        if d in PROTOCOL_BY_INTEGRATION:
            return PROTOCOL_BY_INTEGRATION[d]
    if any(d in NON_DEVICE_INTEGRATIONS for d in domains):
        return "Not a device"
    return f"Other ({domains[0]})" if domains else "unknown"


def _first_env(names) -> str | None:
    for name in names:
        if os.environ.get(name):
            return os.environ[name]
    return None


_IP_IN_NAME = re.compile(r"\b(\d{1,3})[._](\d{1,3})[._](\d{1,3})[._](\d{1,3})\b")
_MAC_IN_NAME = re.compile(r"\b((?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})\b")


def _identifiers_in_name(name: str | None) -> tuple[str | None, str | None]:
    """Pull an IP and/or MAC out of a Home Assistant device name."""
    if not name:
        return None, None
    ip = None
    m = _IP_IN_NAME.search(name)
    if m and all(int(o) <= 255 for o in m.groups()):
        ip = ".".join(m.groups())
    mac_match = _MAC_IN_NAME.search(name)
    mac = mac_match.group(1).lower().replace("-", ":") if mac_match else None
    return ip, mac


def _name_keys(device: dict) -> set[str]:
    """Comparable name forms for a device, from either side of the diff.

    Strips `.local`, case and punctuation so `media-pi.local`, `MediaPi` and
    `media-pi` all collapse to `mediapi`. Names under four characters go -
    "tv" or "pi" would match half the network.
    """
    keys = set()
    for field in ("name", "hostname", "alias", "friendly_name"):
        value = device.get(field)
        if not value:
            continue
        text = str(value).lower().split(".local")[0]
        squashed = re.sub(r"[^a-z0-9]", "", text)
        if len(squashed) >= 4:
            keys.add(squashed)
    return keys


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
