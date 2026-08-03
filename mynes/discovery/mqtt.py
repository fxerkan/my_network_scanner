"""MQTT discovery: Zigbee, Z-Wave, Tasmota and anything already in Home Assistant.

Zigbee and Z-Wave devices are radio-only - they have no IP and cannot be scanned.
The practical way to see them is to read the bridge that already talks to them.
Zigbee2MQTT publishes its full device list on `zigbee2mqtt/bridge/devices`,
Z-Wave JS UI mirrors its nodes, and any integration using Home Assistant's MQTT
discovery publishes retained configs under `homeassistant/+/+/config`.

We subscribe briefly, read the retained messages, and disconnect.
"""

from __future__ import annotations

import json
import os
import threading

from mynes.discovery.base import DiscoveredDevice, DiscoveryBackend

TOPICS = [
    "homeassistant/+/+/config",
    "homeassistant/+/+/+/config",
    "zigbee2mqtt/bridge/devices",
    "zwave/+/+/+/+/+",
    "tasmota/discovery/+/config",
]


class MQTTBackend(DiscoveryBackend):
    name = "mqtt"
    requires = ("paho.mqtt",)

    def __init__(self, host=None, port=None, username=None, password=None):
        self.host = host or os.environ.get("MYNES_MQTT_HOST")
        self.port = int(port or os.environ.get("MYNES_MQTT_PORT") or 1883)
        self.username = username or os.environ.get("MYNES_MQTT_USERNAME")
        self.password = password or os.environ.get("MYNES_MQTT_PASSWORD")

    def available(self):
        ok, reason = super().available()
        if not ok:
            return ok, reason
        if not self.host:
            return False, "no MQTT broker configured (set MYNES_MQTT_HOST)"
        return True, "ok"

    def discover(self, timeout: float = 6.0) -> list[DiscoveredDevice]:
        import paho.mqtt.client as mqtt

        devices: dict[str, DiscoveredDevice] = {}
        done = threading.Event()

        def on_connect(client, *_args):
            for t in TOPICS:
                client.subscribe(t, qos=0)

        def on_message(_client, _ud, msg):
            try:
                payload = json.loads(msg.payload.decode("utf-8", "replace"))
            except (ValueError, UnicodeDecodeError):
                return
            for dev in self._parse(msg.topic, payload):
                existing = devices.get(dev.key())
                if existing:
                    existing.services = sorted(set(existing.services) | set(dev.services))
                    existing.attributes.update(dev.attributes)
                else:
                    devices[dev.key()] = dev

        client = mqtt.Client()
        if self.username:
            client.username_pw_set(self.username, self.password)
        client.on_connect = on_connect
        client.on_message = on_message

        client.connect(self.host, self.port, keepalive=int(timeout) + 10)
        client.loop_start()
        try:
            done.wait(timeout)  # retained messages arrive right after subscribe
        finally:
            client.loop_stop()
            client.disconnect()
        return list(devices.values())

    @staticmethod
    def _parse(topic: str, payload) -> list[DiscoveredDevice]:
        if topic == "zigbee2mqtt/bridge/devices" and isinstance(payload, list):
            out = []
            for node in payload:
                if node.get("type") == "Coordinator":
                    continue
                defn = node.get("definition") or {}
                out.append(
                    DiscoveredDevice(
                        source="mqtt",
                        mac=node.get("ieee_address"),
                        name=node.get("friendly_name"),
                        model=defn.get("model"),
                        vendor=defn.get("vendor") or node.get("manufacturer"),
                        device_type="Zigbee Device",
                        services=["Zigbee2MQTT"],
                        attributes={
                            "protocol": "zigbee",
                            "power_source": node.get("power_source"),
                            "battery_powered": node.get("power_source") == "Battery",
                            "interviewed": node.get("interview_completed"),
                            "network_address": node.get("network_address"),
                            "description": defn.get("description"),
                            "supported": node.get("supported"),
                        },
                    )
                )
            return out

        if topic.startswith("homeassistant/") and isinstance(payload, dict):
            info = payload.get("device") or {}
            ids = info.get("identifiers") or []
            ident = ids[0] if isinstance(ids, list) and ids else (ids or payload.get("unique_id"))
            conns = {c[0]: c[1] for c in (info.get("connections") or []) if len(c) == 2}
            return [
                DiscoveredDevice(
                    source="mqtt",
                    mac=conns.get("mac") or (str(ident) if ident else None),
                    ip=conns.get("ip"),
                    name=info.get("name") or payload.get("name"),
                    model=info.get("model"),
                    vendor=info.get("manufacturer"),
                    device_type="Smart Home",
                    services=["Home Assistant MQTT"],
                    attributes={
                        "protocol": "mqtt",
                        "ha_component": topic.split("/")[1],
                        "sw_version": info.get("sw_version"),
                        "via_device": info.get("via_device"),
                    },
                )
            ]

        if topic.startswith("tasmota/discovery/") and isinstance(payload, dict):
            return [
                DiscoveredDevice(
                    source="mqtt",
                    mac=payload.get("mac"),
                    ip=payload.get("ip"),
                    name=payload.get("dn") or payload.get("hn"),
                    model=payload.get("md"),
                    vendor="Tasmota",
                    device_type="IoT Device",
                    services=["Tasmota"],
                    attributes={"protocol": "wifi", "sw_version": payload.get("sw")},
                )
            ]

        if topic.startswith("zwave/") and isinstance(payload, dict):
            parts = topic.split("/")
            return [
                DiscoveredDevice(
                    source="mqtt",
                    mac=f"zwave-node-{parts[1]}",
                    name=parts[1],
                    device_type="Z-Wave Device",
                    services=["Z-Wave JS"],
                    attributes={"protocol": "zwave"},
                )
            ]

        return []


def discover(timeout: float = 6.0, **kwargs) -> list[DiscoveredDevice]:
    return MQTTBackend(**kwargs).safe_discover(timeout=timeout)


if __name__ == "__main__":
    for d in discover(8.0):
        print(f"{d.mac or d.ip:<24} {d.name or '?':<30} {d.device_type} {d.services}")
