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

    # Canonical names (a tuple is kept so a call site can still pass overrides).
    # HA_URL/HA_TOKEN are canonical; MYNES_HA_* is what the CasaOS/Umbrel app
    # manifests expose, and was silently ignored until it was read here too.
    URL_VARS = ("HA_URL", "MYNES_HA_URL")
    TOKEN_VARS = ("HA_TOKEN", "MYNES_HA_TOKEN")

    def __init__(self, url: str | None = None, token: str | None = None, timeout: int = 15):
        # Explicit args > what was saved in Settings (data/home_assistant.json,
        # never the tracked config.json) > environment.
        saved = load_settings()
        self.url = (url or saved.get("url") or _first_env(self.URL_VARS) or "").rstrip("/")
        self.token = token or saved.get("token") or _first_env(self.TOKEN_VARS)
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
            return {"ok": False, "error": "HA_URL and HA_TOKEN are required"}
        try:
            return {"ok": True, **self._get("/api/config")}
        except urllib.error.HTTPError as e:
            # 401/403 from HA both mean the long-lived token is the problem
            # (missing, expired, revoked, or not admin) - say so instead of a bare code.
            hint = "check HA_TOKEN (invalid, expired, or revoked)" if e.code in (401, 403) else e.reason
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
        raw = self._registry_raw()
        if raw is None:
            return []
        devices, entities, entries, areas = raw["devices"], raw["entities"], raw["entries"], raw["areas"]
        return _registry_rows(devices, entities, entries, areas)

    def _registry_raw(self) -> dict | None:
        """The four WebSocket-only registries, unprocessed. None when the
        websocket-client package is missing or auth fails."""
        try:
            import websocket
        except ImportError:
            return None

        ws_url = self.url.replace("https://", "wss://").replace("http://", "ws://") + "/api/websocket"
        ws = websocket.create_connection(ws_url, timeout=self.timeout)
        try:
            json.loads(ws.recv())  # auth_required
            ws.send(json.dumps({"type": "auth", "access_token": self.token}))
            if json.loads(ws.recv()).get("type") != "auth_ok":
                return None

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
            areas = request(4, "config/area_registry/list")
        finally:
            ws.close()
        return {"devices": devices, "entities": entities, "entries": entries, "areas": areas}

    def inventory(self, mynes_devices: list[dict], inactive_days: int = 14) -> dict:
        """Every HA registry device with status, addresses and its MyNeS match.
        See build_inventory() for the classification rules."""
        raw = self._registry_raw()
        if raw is None:
            raise RuntimeError("device registry unavailable (websocket-client missing or auth failed)")
        states = self.states()
        return build_inventory(raw["devices"], raw["entities"], raw["entries"], raw["areas"],
                               states, mynes_devices, inactive_days=inactive_days)


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



def _registry_rows(devices, entities, entries, areas) -> list[dict]:
    """Pure: raw registries -> the condensed rows device_registry() returns."""
    # config_entry_id -> integration name ("zha", "matter", "zwave_js", ...)
    integration = {e["entry_id"]: e.get("domain") for e in entries if isinstance(e, dict)}
    area_name = {a.get("area_id"): a.get("name") for a in areas if isinstance(a, dict)}
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
                "area": area_name.get(d.get("area_id")),
            }
        )
    return out


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



# ---------------------------------------------------------------------------
# Settings saved from the UI + enrichment of MyNeS devices from HA's registry
# ---------------------------------------------------------------------------

SETTINGS_FILE = "home_assistant.json"


def load_settings() -> dict:
    """UI-saved HA settings from data/ (gitignored, holds the token)."""
    try:
        from mynes.paths import load_local
        return load_local(SETTINGS_FILE) or {}
    except Exception:  # noqa: BLE001
        return {}


def save_settings(patch: dict) -> dict:
    """Merge and persist. An empty token keeps the stored one, so re-saving the
    form (whose token field always comes back blank) never wipes it."""
    from mynes.paths import save_local
    current = load_settings()
    for key in ("url", "auto_enrich"):
        if key in patch:
            current[key] = patch[key]
    if patch.get("token"):
        current["token"] = patch["token"]
    if patch.get("clear_token"):
        current.pop("token", None)
    if isinstance(current.get("url"), str):
        current["url"] = current["url"].strip().rstrip("/")
    return save_local(SETTINGS_FILE, current)


def _norm_mac(value) -> str | None:
    if not value:
        return None
    mac = str(value).lower().replace("-", ":")
    return mac if re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac) else None


# Scanner placeholders an HA name may replace: "Espressif IoT Device",
# "Unknown", a bare IP/MAC, "<Vendor> 112"-style vendor+octet names.
_GENERIC_ALIAS = re.compile(
    r"^(unknown|bilinmeyen|.*\b(iot device|smart home|device)\b.*|[0-9a-f:.-]+|.+ \d{1,3})$", re.I)


# The HA integration that owns a device is strong evidence of what it is.
HA_INTEGRATION_TYPES = {
    "samsungtv": "Smart TV", "androidtv_remote": "Smart TV", "androidtv": "Smart TV", "webostv": "Smart TV",
    "braviatv": "Smart TV", "philips_js": "Smart TV", "roku": "Streaming Device", "apple_tv": "Streaming Device",
    "philips_airpurifier_coap": "Air Purifier", "dyson_local": "Air Purifier", "xiaomi_miio_airpurifier": "Air Purifier",
    "fujitsu_airstage": "Air Conditioner", "daikin": "Air Conditioner", "mitsubishi": "Air Conditioner",
    "roborock": "Vacuum Cleaner", "ecovacs": "Vacuum Cleaner", "dreame_vacuum": "Vacuum Cleaner",
    "tplink_deco": "Access Point", "tapo_control": "IP Camera", "onvif": "IP Camera", "reolink": "IP Camera",
    "anker_solix": "Power Station", "sonos": "Smart Speaker", "hue": "Smart Light", "yeelight": "Smart Light",
    "wled": "Smart Light", "brother": "Printer", "ipp": "Printer", "synology_dsm": "NAS", "qnap": "NAS",
}
_HA_MODEL_TYPES = (
    (re.compile(r"pura|litter|t[345]\b", re.I), "Pet Litter Box"),
    (re.compile(r"feeder|fresh element|d[34]\b", re.I), "Pet Feeder"),
    (re.compile(r"eversweet|fountain|ctw", re.I), "Pet Water Fountain"),
    (re.compile(r"\bl5\d\d|bulb", re.I), "Smart Light"),
)


def ha_device_type(h: dict) -> str | None:
    """Pure: the MyNeS type HA's registry implies for one device, if any."""
    for _rx, dtype in _HA_MODEL_TYPES:
        if _rx.search(h.get("model") or ""):
            return dtype
    for domain in h.get("integrations") or []:
        if domain in HA_INTEGRATION_TYPES:
            return HA_INTEGRATION_TYPES[domain]
    return None


def enrich_devices(mynes_devices: list, registry: list, *, fill_alias: bool = True,
                   fill_location: bool = True, fill_vendor: bool = True) -> list:
    """Pure: copy what Home Assistant knows onto the matching MyNeS devices.

    Matches on MAC (the registry's ``connections``), then on an IP embedded
    in a ``generic``-style device name. Always records ``home_assistant``
    (name, area, manufacturer, model, integrations, protocol) on the device.
    Fills alias / location / vendor ONLY where MyNeS has nothing better: a
    field the user set (``user_modified``) is never touched, and an alias is
    only replaced when it is a scanner placeholder. Mutates ``mynes_devices``
    in place; returns ``[{key, field, old, new}]`` for the UI and the log.
    """
    by_mac, by_ip = {}, {}
    for h in registry or []:
        if h.get("disabled") or h.get("protocol") == "Not a device":
            continue
        mac = _norm_mac(h.get("mac"))
        if mac and (mac not in by_mac or (h.get("model") and not by_mac[mac].get("model"))):
            by_mac[mac] = h       # prefer the real device over a MAC-only stub
        if h.get("ip"):
            by_ip.setdefault(h["ip"], h)

    changes = []
    for d in mynes_devices:
        h = by_mac.get(_norm_mac(d.get("mac")) or "") or by_ip.get(d.get("ip") or "")
        if not h:
            continue
        key = d.get("ip") or d.get("mac")
        d["home_assistant"] = {
            "id": h.get("id"), "name": h.get("name"), "area": h.get("area"),
            "manufacturer": h.get("manufacturer"), "model": h.get("model"),
            "integrations": h.get("integrations") or [], "protocol": h.get("protocol"),
        }
        user = d.get("user_modified") or {}

        def put(field, value):
            if not value or field in user or d.get(field) == value:
                return
            changes.append({"key": key, "field": field, "old": d.get(field), "new": value})
            d[field] = value

        if fill_alias and d.get("alias_source") != "user":
            cur = (d.get("alias") or "").strip()
            from mynes.analysis.identity import is_placeholder_alias
            if not cur or _GENERIC_ALIAS.match(cur) or is_placeholder_alias(cur, d.get("vendor")):
                put("alias", h.get("name"))
        if fill_location and not d.get("location"):
            put("location", h.get("area"))
        if fill_vendor and (d.get("vendor") or "Unknown") in ("Unknown", "Bilinmeyen"):
            put("vendor", h.get("manufacturer"))
        # The owning integration/model pins the type; identity.apply_identity
        # keeps it sticky and still never overrides a user edit.
        dtype = ha_device_type(h)
        if dtype:
            from mynes.analysis.identity import apply_identity
            for field, old, new in apply_identity(d, {
                    "device_type": dtype, "confidence": 0.94, "name": None, "vendor": None,
                    "model": h.get("model"), "hostname": None,
                    "reasons": [f"Home Assistant: {', '.join(h.get('integrations') or [])} {h.get('model') or ''}".strip()]}):
                if field == "device_type":
                    changes.append({"key": key, "field": field, "old": old, "new": new})
    return changes



# ---------------------------------------------------------------------------
# Inventory (Compare) + selective import
# ---------------------------------------------------------------------------

# Registry entries that are not physical devices: HACS repositories and
# frontend plugins, service/helper entries, cloud scenes ("Açıl Susam" is a
# Tuya *scene*, not hardware), integration stubs.
_NOT_DEVICE_MODEL = re.compile(r"\b(scene|integration|plugin|automation|script|group|helper|account)\b", re.I)
DEAD_STATES = {"unavailable", "unknown", "", None}


def _parse_ts(value):
    from datetime import datetime
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def build_inventory(devices, entities, entries, areas, states, mynes_devices,
                    inactive_days: int = 14, now=None) -> dict:
    """Pure: HA registries + states + MyNeS devices -> one row per HA device.

    status is one of:
      active        at least one enabled entity reports a real state that
                    HA refreshed within ``inactive_days``
      inactive      no entities, or every entity is unavailable/unknown, or
                    nothing was reported for longer than ``inactive_days``
                    (gone hardware: an old Xbox, a removed bulb)
      disabled      the user disabled the device in HA (Jellyfin clients)
      not_a_device  services, HACS repositories/plugins, helper entries and
                    cloud scenes (a Tuya scene such as "Açıl Susam")
    Each row also carries IP/MAC (from connections, device_tracker
    attributes, any entity attribute, or an address embedded in the name),
    integrations, protocol, area, model, the freshest state time and the
    matching MyNeS device key (ip, or mac for radio devices), if any.
    """
    from datetime import datetime, timedelta, timezone
    now = now or datetime.now(timezone.utc)
    base = {r["id"]: r for r in _registry_rows(devices, entities, entries, areas)}
    raw_by_id = {d.get("id"): d for d in devices}
    state_of = {s.get("entity_id"): s for s in states or [] if isinstance(s, dict)}

    ents_by_dev: dict = {}
    for e in entities or []:
        if e.get("device_id") and not e.get("disabled_by"):
            ents_by_dev.setdefault(e["device_id"], []).append(e.get("entity_id"))

    # Any entity attribute pairing a MAC with an IP (tplink_deco trackers,
    # ping, mobile_app) is an address book for the whole LAN.
    ip_by_mac = {}
    for st in states or []:
        attrs = st.get("attributes") or {}
        mac = _norm_mac(attrs.get("mac") or attrs.get("mac_address"))
        ip = attrs.get("ip") or attrs.get("ip_address")
        if mac and ip:
            ip_by_mac[mac] = ip

    def norm(v):
        return str(v).lower().replace("-", ":") if v else None

    my_by_mac = {norm(d.get("mac")): d for d in mynes_devices if d.get("mac")}
    my_by_ip = {d.get("ip"): d for d in mynes_devices if d.get("ip")}
    my_by_ha = {(d.get("home_assistant") or {}).get("id"): d for d in mynes_devices
                if (d.get("home_assistant") or {}).get("id")}

    rows = []
    cutoff = now - timedelta(days=inactive_days)
    for dev_id, row in base.items():
        raw = raw_by_id.get(dev_id) or {}
        ent_ids = ents_by_dev.get(dev_id, [])
        live = [state_of[e] for e in ent_ids if e in state_of]
        alive = [s for s in live if s.get("state") not in DEAD_STATES]
        fresh = None
        for s in live:
            ts = _parse_ts(s.get("last_reported")) or _parse_ts(s.get("last_updated")) or _parse_ts(s.get("last_changed"))
            if ts and (fresh is None or ts > fresh):
                fresh = ts
        fresh_alive = None
        for s in alive:
            ts = _parse_ts(s.get("last_reported")) or _parse_ts(s.get("last_updated"))
            if ts and (fresh_alive is None or ts > fresh_alive):
                fresh_alive = ts

        # Addresses: registry connections, a bare 12-hex MAC used as the name
        # (fujitsu_airstage names devices "A841F4180165"), entity attributes,
        # then the LAN map.
        mac = _norm_mac(row.get("mac"))
        bare = re.fullmatch(r"[0-9A-Fa-f]{12}", (row.get("name") or "").strip())
        if not mac and bare:
            mac = _norm_mac(":".join(bare.group(0)[i:i + 2] for i in range(0, 12, 2)))
        ip = row.get("ip")
        for s in live:
            attrs = s.get("attributes") or {}
            mac = mac or _norm_mac(attrs.get("mac") or attrs.get("mac_address"))
            ip = ip or attrs.get("ip") or attrs.get("ip_address")
        ip = ip or (ip_by_mac.get(mac) if mac else None)

        if raw.get("entry_type") == "service" or row.get("protocol") == "Not a device" \
                or _NOT_DEVICE_MODEL.search(row.get("model") or "") \
                or (row.get("manufacturer") or "").lower() in ("hacs.xyz", "custom-cards"):
            status, why = "not_a_device", "service / plugin / scene entry"
        elif raw.get("disabled_by"):
            status, why = "disabled", f"disabled by {raw.get('disabled_by')}"
        elif not ent_ids:
            status, why = "inactive", "no enabled entities"
        elif not alive:
            status, why = "inactive", "every entity is unavailable/unknown"
        elif fresh_alive and fresh_alive < cutoff:
            status, why = "inactive", f"no update for {(now - fresh_alive).days} days"
        else:
            status, why = "active", f"{len(alive)}/{len(live)} entities reporting"

        match, method = my_by_ha.get(dev_id), "home_assistant"
        if match is None and mac and my_by_mac.get(norm(mac)):
            match, method = my_by_mac[norm(mac)], "mac"
        if match is None and ip and my_by_ip.get(ip):
            match, method = my_by_ip[ip], "ip"
        if match is None and status in ("active", "inactive"):
            # Cloud integrations (Dyson, Roborock, Anker) carry no MAC/IP.
            # Fall back to the name: an exact squashed match, else a unique
            # containment ("Q8 Max Pro+" in "Roborock Q8 Max Pro+") - without
            # it the default selection would import duplicates.
            keys = {k for k in _name_keys(row) if len(k) >= 6}
            exact = [d for d in mynes_devices if keys & _name_keys(d)]
            loose = [d for d in mynes_devices
                     if any(k in mk for k in keys for mk in _name_keys(d))]
            pick = exact if len(exact) == 1 else (loose if len(loose) == 1 else [])
            if pick:
                match, method = pick[0], "name"
        if match is None:
            method = None
        rows.append({
            **row, "mac": mac, "ip": ip, "status": status, "status_reason": why,
            "entities": len(ent_ids), "entities_alive": len(alive),
            "last_seen": fresh.isoformat() if fresh else None,
            "entry_type": raw.get("entry_type"),
            "mynes_key": (match.get("ip") or match.get("mac")) if match else None,
            "mynes_name": (match.get("alias") or match.get("hostname")) if match else None,
            "match_method": method,
        })

    order = {"active": 0, "inactive": 1, "disabled": 2, "not_a_device": 3}
    rows.sort(key=lambda r: (order[r["status"]], r["mynes_key"] is not None, (r.get("name") or "").lower()))
    counts = {k: sum(1 for r in rows if r["status"] == k) for k in order}
    return {"devices": rows, "counts": counts,
            "matched": sum(1 for r in rows if r["mynes_key"]),
            "inactive_days": inactive_days}


# Protocol -> type for HA devices MyNeS cannot see on the wire.
_PROTOCOL_TYPES = {"Zigbee": "Smart Home", "Z-Wave": "Smart Home", "Matter": "Smart Home",
                   "Thread": "Smart Home", "Bluetooth": "Bluetooth Device", "Cloud": "Smart Home",
                   "Companion app": "Smartphone"}


def import_devices(mynes_devices: list, rows: list) -> list:
    """Import the chosen HA inventory rows into the MyNeS device list.

    - A row that matches a MyNeS device is folded in with enrich_devices(),
      the same non-destructive merge the automatic enrichment uses: it fills
      empty or placeholder fields and never touches a user edit.
    - A row with no match becomes a new MyNeS device. It has no IP on the
      wire (Zigbee, BLE, cloud), so it is stored the way radio devices are:
      ``ip`` empty and keyed by its MAC, or by ``ha:<device_id>`` when HA
      knows no MAC. ``discovery_only`` keeps scans from marking it offline,
      and offline preservation keeps any device with an alias, so scans never
      drop it. ``source: home_assistant`` says where it came from. An HA
      device with an IP but no MAC is created without the IP, so a later ARP
      sweep that finds the real MAC cannot turn it into a duplicate.
    Mutates ``mynes_devices``; returns [{id, name, action, key}] per row.
    """
    from datetime import datetime
    now = datetime.now().isoformat()
    out = []
    by_key = {(d.get("ip") or d.get("mac")): d for d in mynes_devices}
    for r in rows:
        target = by_key.get(r.get("mynes_key")) if r.get("mynes_key") else None
        if target is None:
            target = next((d for d in mynes_devices
                           if (d.get("home_assistant") or {}).get("id") == r.get("id")), None)
        if target is not None:
            changes = enrich_devices([target], [r])
            out.append({"id": r.get("id"), "name": r.get("name"), "action": "updated",
                        "key": target.get("ip") or target.get("mac"),
                        "fields": sorted({c["field"] for c in changes})})
            continue
        mac = _norm_mac(r.get("mac"))
        key = mac or f"ha:{r.get('id')}"
        dtype = ha_device_type(r) or _PROTOCOL_TYPES.get(r.get("protocol") or "", "Smart Home")
        dev = {
            "ip": "", "mac": key, "alias": r.get("name") or key, "alias_source": "home_assistant",
            "hostname": "", "vendor": r.get("manufacturer") or "Unknown", "device_type": dtype,
            "device_type_source": "auto", "location": r.get("area") or "", "notes": "",
            "status": "online" if r.get("status") == "active" else "offline",
            "last_seen": r.get("last_seen") or now, "open_ports": [], "discovery_only": True,
            "source": "home_assistant", "model": r.get("model"),
            "home_assistant": {"id": r.get("id"), "name": r.get("name"), "area": r.get("area"),
                               "manufacturer": r.get("manufacturer"), "model": r.get("model"),
                               "integrations": r.get("integrations") or [], "protocol": r.get("protocol"),
                               "ip": r.get("ip"), "status": r.get("status")},
            "analysis_data": {}, "imported_at": now,
        }
        mynes_devices.append(dev)
        by_key[key] = dev
        out.append({"id": r.get("id"), "name": r.get("name"), "action": "created", "key": key})
    return out


LAST_ENRICH: dict = {}


def enrich_scanner(scanner, force: bool = False) -> dict:
    """Pull HA's device registry and enrich the scanner's live device list.

    Runs after every scan when HA is configured and ``auto_enrich`` is not
    switched off; ``force`` runs it regardless (the "Enrich now" button).
    Never raises - HA being down must not break a scan. Records the outcome
    in LAST_ENRICH for the settings card.
    """
    from datetime import datetime, timezone
    settings = load_settings()
    client = HomeAssistantClient()
    result = {"at": datetime.now(timezone.utc).isoformat(), "ok": False, "matched": 0, "changes": []}
    if not client.configured():
        result["error"] = "Home Assistant is not configured"
    elif not force and settings.get("auto_enrich") is False:
        result["error"] = "auto enrich is off"
    else:
        try:
            registry = client.device_registry()
            devices = scanner.devices
            result["changes"] = enrich_devices(devices, registry)
            result["matched"] = sum(1 for d in devices if d.get("home_assistant"))
            result["registry_devices"] = len(registry)
            result["ok"] = True
        except Exception as e:  # noqa: BLE001
            result["error"] = f"{type(e).__name__}: {e}"
            log.warning("Home Assistant enrich failed: %s", e)
    LAST_ENRICH.clear()
    LAST_ENRICH.update(result)
    return result

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

    # Enrichment: fills placeholders, never a user edit, records HA's view.
    mine = [
        {"ip": "192.168.1.109", "mac": "C0:5D:89:CB:6B:1C", "alias": "Espressif IoT Device", "vendor": "Espressif Inc."},
        {"ip": "192.168.1.32", "mac": "68:79:c4:f9:2d:ed", "alias": "Mutfak Temizleyici", "location": "",
         "user_modified": {"alias": "Mutfak Temizleyici"}},
        {"ip": "192.168.1.200", "mac": "0e:52:43:3b:72:56", "alias": "192.168.1.200", "vendor": "Unknown"},
    ]
    reg = [
        {"id": "a", "name": "Totolet", "mac": "c0:5d:89:cb:6b:1c", "model": "Petkit Pura Max", "manufacturer": "Petkit", "area": None},
        {"id": "b", "name": "Mutfak", "mac": "68-79-C4-F9-2D-ED", "manufacturer": "Philips", "area": "Kitchen"},
        {"id": "c", "name": "Ignored", "mac": "0e:52:43:3b:72:56", "disabled": True},
    ]
    ch = enrich_devices(mine, reg)
    assert mine[0]["alias"] == "Totolet" and mine[0]["home_assistant"]["model"] == "Petkit Pura Max"
    assert mine[0]["vendor"] == "Espressif Inc."                      # a real vendor is kept
    assert mine[1]["alias"] == "Mutfak Temizleyici"                   # user edit wins
    assert mine[1]["location"] == "Kitchen"                           # empty field filled
    assert "home_assistant" not in mine[2]                            # disabled entry ignored
    assert {(c["key"], c["field"]) for c in ch} == {("192.168.1.109", "alias"), ("192.168.1.32", "location"),
                                                    ("192.168.1.32", "vendor"), ("192.168.1.109", "device_type")}
    assert enrich_devices(mine, reg) == []                            # idempotent
    assert ha_device_type({"integrations": ["samsungtv", "dlna_dmr"]}) == "Smart TV"
    assert ha_device_type({"model": "Petkit Pura Max", "integrations": ["petkit"]}) == "Pet Litter Box"
    tv = [{"ip": "192.168.1.155", "mac": "d8:e0:e1:aa:a4:9a", "alias": "Samsung Smartphone", "device_type": "Smartphone"}]
    enrich_devices(tv, [{"id": "t", "name": "[TV]FxTV", "mac": "d8:e0:e1:aa:a4:9a", "model": "UE55MU7000",
                         "integrations": ["samsungtv"]}])
    assert tv[0]["device_type"] == "Smart TV" and tv[0]["alias"] == "[TV]FxTV", tv

    # Inventory: status classification, addresses, MyNeS match.
    from datetime import datetime, timezone
    now = datetime(2026, 11, 24, 12, 0, tzinfo=timezone.utc)
    reg_devices = [
        {"id": "tv", "name": "[TV]FxTV", "model": "UE55MU7000", "config_entries": ["e_sam"],
         "connections": [["mac", "d8:e0:e1:aa:a4:9a"]]},
        {"id": "xbox", "name": "XBOXONEXFX", "model": "DLNA", "config_entries": ["e_jf"], "disabled_by": "user"},
        {"id": "scene", "name": "Açıl Susam", "model": "Tuya Scene", "config_entries": ["e_tuya"]},
        {"id": "hacs", "name": "button-card", "model": "plugin", "manufacturer": "custom-cards",
         "config_entries": ["e_hacs"], "entry_type": "service"},
        {"id": "old", "name": "Old Bulb", "config_entries": ["e_tp"], "connections": [["mac", "aa:bb:cc:00:00:09"]]},
        {"id": "zb", "name": "Kapı Sensörü", "model": "SNZB-04", "manufacturer": "SONOFF",
         "config_entries": ["e_zha"], "area_id": "hol"},
        {"id": "deco_client", "name": "3C-64-CF-BC-64-03", "config_entries": ["e_deco"]},
    ]
    reg_entities = [
        {"entity_id": "media_player.tv", "device_id": "tv"},
        {"entity_id": "light.old", "device_id": "old"},
        {"entity_id": "binary_sensor.door", "device_id": "zb"},
        {"entity_id": "device_tracker.l510", "device_id": "deco_client"},
    ]
    reg_entries = [{"entry_id": "e_sam", "domain": "samsungtv"}, {"entry_id": "e_jf", "domain": "jellyfin"},
                   {"entry_id": "e_tuya", "domain": "tuya"}, {"entry_id": "e_hacs", "domain": "hacs"},
                   {"entry_id": "e_tp", "domain": "tplink"}, {"entry_id": "e_zha", "domain": "zha"},
                   {"entry_id": "e_deco", "domain": "tplink_deco"}]
    st = [
        {"entity_id": "media_player.tv", "state": "off", "last_reported": "2026-11-24T11:00:00+00:00"},
        {"entity_id": "light.old", "state": "unavailable", "last_changed": "2026-09-01T00:00:00+00:00"},
        {"entity_id": "binary_sensor.door", "state": "off", "last_reported": "2026-11-24T10:00:00+00:00"},
        {"entity_id": "device_tracker.l510", "state": "home", "last_reported": "2026-11-24T11:30:00+00:00",
         "attributes": {"ip": "192.168.1.103", "mac": "3C-64-CF-BC-64-03"}},
    ]
    reg_devices.append({"id": "robo", "name": "Q8 Max Pro+", "manufacturer": "Roborock", "config_entries": ["e_rr"]})
    reg_entities.append({"entity_id": "vacuum.q8", "device_id": "robo"})
    reg_entries.append({"entry_id": "e_rr", "domain": "roborock"})
    st.append({"entity_id": "vacuum.q8", "state": "docked", "last_reported": "2026-11-24T11:00:00+00:00"})
    mine = [{"ip": "192.168.1.155", "mac": "d8:e0:e1:aa:a4:9a", "alias": "Samsung Smart TV"},
            {"ip": "192.168.1.60", "mac": "24:9e:7d:24:11:15", "alias": "Roborock Q8 Max Pro+"}]
    inv = build_inventory(reg_devices, reg_entities, reg_entries, [{"area_id": "hol", "name": "Hol"}],
                          st, mine, now=now)
    by = {r["id"]: r for r in inv["devices"]}
    assert by["tv"]["status"] == "active" and by["tv"]["mynes_key"] == "192.168.1.155"
    assert by["xbox"]["status"] == "disabled"
    assert by["scene"]["status"] == "not_a_device" and by["hacs"]["status"] == "not_a_device"
    assert by["old"]["status"] == "inactive"
    assert by["zb"]["status"] == "active" and by["zb"]["area"] == "Hol" and by["zb"]["mynes_key"] is None
    assert by["deco_client"]["ip"] == "192.168.1.103" and by["deco_client"]["mac"] == "3c:64:cf:bc:64:03"
    assert inv["counts"] == {"active": 4, "inactive": 1, "disabled": 1, "not_a_device": 2}, inv["counts"]
    assert by["robo"]["mynes_key"] == "192.168.1.60" and by["robo"]["match_method"] == "name"
    inv2 = build_inventory([{"id": "ac", "name": "A841F4180165", "config_entries": ["e"]},
                            {"id": "acct", "name": "Erkan (TR)", "model": "Account", "config_entries": ["e"]}],
                           [{"entity_id": "climate.ac", "device_id": "ac"}], [{"entry_id": "e", "domain": "x"}], [],
                           [{"entity_id": "climate.ac", "state": "cool", "last_reported": "2026-11-24T11:00:00+00:00"}],
                           [{"ip": "192.168.1.84", "mac": "a8:41:f4:18:01:65"}], now=now)
    b2 = {r["id"]: r for r in inv2["devices"]}
    assert b2["ac"]["mac"] == "a8:41:f4:18:01:65" and b2["ac"]["mynes_key"] == "192.168.1.84"
    assert b2["acct"]["status"] == "not_a_device"

    # Import: the match is enriched, the radio device is created keyed ha:<id>.
    res = import_devices(mine, [by["tv"], by["zb"]])
    assert [r["action"] for r in res] == ["updated", "created"], res
    zb = mine[-1]
    assert zb["mac"] == "ha:zb" and zb["ip"] == "" and zb["discovery_only"] and zb["location"] == "Hol"
    assert import_devices(mine, [by["zb"]])[0]["action"] == "updated"   # idempotent: found by HA id
    assert len(mine) == 3
    assert build_state({**dev, "status": "offline"})["state"] == "not_home"

    scanner = build_scanner_payloads([dev], [{"severity": "critical"}])
    assert any(p.get("alerts_critical") == 1 for _, p, _ in scanner)
    print("home_assistant demo OK")


if __name__ == "__main__":
    demo()
