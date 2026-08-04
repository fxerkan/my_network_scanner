# MyNeS — My Network Scanner

[![Docker Pulls](https://img.shields.io/docker/pulls/fxerkan/my_network_scanner)](https://hub.docker.com/r/fxerkan/my_network_scanner)
[![Docker Image Size](https://img.shields.io/docker/image-size/fxerkan/my_network_scanner/latest)](https://hub.docker.com/r/fxerkan/my_network_scanner)
[![GitHub Release](https://img.shields.io/github/v/release/fxerkan/my_network_scanner)](https://github.com/fxerkan/my_network_scanner/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/fxerkan/my_network_scanner/blob/main/LICENSE)

**See every device on your home network — including the ones an IP scan cannot find.**

An IP scan of my LAN found 29 devices. There were about 60. Everything on Zigbee and Z-Wave has
no IP address, so an IP scan is blind to it — and the inventory was never real.

MyNeS discovers devices over **ARP, mDNS/Bonjour, SSDP/UPnP, Matter, Bluetooth LE and MQTT**.
That last one is the trick: reading retained Zigbee2MQTT / Z-Wave JS / Tasmota / Home Assistant
discovery topics is the only way to see a radio device that has no IP at all. Everything lands
in one inventory.

No cloud, no account, no telemetry. Everything stays on your LAN.

---

## Quick start

```yaml
services:
  mynes:
    image: fxerkan/my_network_scanner:latest
    container_name: mynes
    # Host networking is what lets it actually see the LAN. See the note below.
    network_mode: host
    cap_add:
      - NET_ADMIN
      - NET_RAW
    volumes:
      - ./data:/app/data
      - ./config:/app/config
    environment:
      MYNES_PORT: 5883
      MYNES_PASSWORD: ""        # auto-generated on first start if empty
      MYNES_MQTT_HOST: ""       # optional — reveals Zigbee / Z-Wave / Tasmota devices
      MYNES_HA_URL: ""          # optional — Home Assistant integration
      MYNES_HA_TOKEN: ""
    restart: unless-stopped
```

```bash
docker compose up -d
```

Or without compose:

```bash
docker run -d \
  --name mynes \
  --network host \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  -v "$(pwd)/data:/app/data" \
  -v "$(pwd)/config:/app/config" \
  -e MYNES_PORT=5883 \
  --restart unless-stopped \
  fxerkan/my_network_scanner:latest
```

Then open **http://\<your-server-ip\>:5883**.

---

## Why host networking and NET_RAW?

MyNeS sends raw ARP frames and listens for mDNS/SSDP multicast. Both require the host network
namespace — from a bridge network it can only see the bridge, not the LAN.

- `NET_RAW` lets it build ARP frames.
- `NET_ADMIN` lets it read interface state.
- It does **not** run as root (`USER scanner`, uid 1000) and it is **not** `privileged`.
- Without these capabilities it does not fail: it degrades to a ping sweep plus the OS ARP cache
  and finds fewer devices. `GET /api/capabilities` tells you exactly what is missing and why.

Docker Desktop (macOS/Windows) does not fully support host networking. There, drop
`network_mode: host` and use `ports: ["5883:5883"]` instead, accepting reduced discovery.

> MyNeS is a scanner. Only scan networks you own.

---

## What it does

- **Multi-protocol discovery** — ARP, mDNS/Bonjour, SSDP/UPnP, Matter, Bluetooth LE, MQTT.
  Zigbee bulbs behind Zigbee2MQTT and Z-Wave sensors behind Z-Wave JS appear next to your laptops.
- **Identification** — vendor lookup over a 1000+ entry OUI database, hostname pattern analysis,
  port signatures, and automatic device-type classification (router, NAS, camera, console, smart
  plug, …). Identification regexes are editable in the UI.
- **Views** — device grid, table, network topology, force-directed graph, and a home floor plan
  you can pin devices onto.
- **Scan history** — when a device first appeared, when it went quiet.
- **Monitoring and alerts** — rule-based alerts on new, missing or changed devices, delivered by
  Web Push (MyNeS runs its own, no third-party relay), webhook, e-mail, or Home Assistant.
- **Two-way Home Assistant integration** — MQTT Discovery pushes every device in as an entity;
  the REST/WebSocket side pulls HA's device registry back and diffs it against what is actually
  on the wire.
- **Optional deep analysis** — port and service detection via nmap, SSH/SNMP interrogation with
  credentials you store encrypted (Fernet + PBKDF2-HMAC-SHA256, 100k iterations).
- **Turkish and English UI**, light and dark themes, installable as a PWA.

Optional dependencies degrade gracefully: a missing Bluetooth adapter or an unreachable MQTT
broker disables that one source, never the scan.

---

## Environment variables

| Variable | Description | Default |
| --- | --- | --- |
| `MYNES_PORT` | Web interface port | `5883` |
| `MYNES_PASSWORD` | Master password encrypting stored device credentials | auto-generated |
| `MYNES_MQTT_HOST` | MQTT broker host — reveals Zigbee / Z-Wave / Tasmota devices | empty |
| `MYNES_MQTT_USERNAME` | MQTT username | empty |
| `MYNES_MQTT_PASSWORD` | MQTT password | empty |
| `MYNES_HA_URL` | Home Assistant base URL, e.g. `http://homeassistant.local:8123` | empty |
| `MYNES_HA_TOKEN` | Home Assistant long-lived access token | empty |
| `MYNES_CONFIG_DIR` / `MYNES_DATA_DIR` | Override the config/data paths | `/app/config`, `/app/data` |
| `TZ` | Container timezone | `UTC` |

`HA_URL` / `HA_TOKEN` are accepted as bare aliases. `LAN_SCANNER_PASSWORD` still works as a
legacy alias for `MYNES_PASSWORD`.

## Volumes

| Path | Contents |
| --- | --- |
| `/app/data` | Device inventory, scan history, alerts |
| `/app/config` | Configuration and encrypted credentials |

## Tags and architectures

`latest`, `1.3`, `1.3.0` — built for **linux/amd64** and **linux/arm64**, so a Raspberry Pi or
Orange Pi works without changes.

## Health check

The image ships a health check against `GET /api/version`. `GET /api/capabilities` is the one to
read when discovery finds less than you expect — it reports which protocol backends and
privileges are actually available.

---

## Links

- **Source and docs:** <https://github.com/fxerkan/my_network_scanner>
- **Issues:** <https://github.com/fxerkan/my_network_scanner/issues>
- **Full deployment guide:** [docs/docker-deployment.md](https://github.com/fxerkan/my_network_scanner/blob/main/docs/docker-deployment.md)

MIT licensed. Made by [fxerkan](https://github.com/fxerkan).
