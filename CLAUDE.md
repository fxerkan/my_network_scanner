# CLAUDE.md

Guidance for Claude Code (claude.ai/code) when working in this repository.

## Overview

MyNeS (My Network Scanner) is a Flask application that discovers, identifies and
monitors every device on a home network — including the ones an IP scan cannot
see (Bluetooth LE, Zigbee, Z-Wave) — and integrates with Home Assistant.

Target users run home labs: Raspberry Pi / Orange Pi clusters, NAS boxes, AI
workstations, and a Home Assistant install. Design decisions should favour that
audience: no cloud dependency, works on a LAN, degrades gracefully when an
optional dependency or privilege is missing.

## Commands

```bash
# One command, any OS: creates the venv, installs deps, checks nmap, runs.
python scripts/run.py

# Manual
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[all]"
python -m mynes                      # or: mynes

# Tests
.venv/bin/python -m pytest tests/ -q

# Individual module self-checks (each is runnable and asserts its own logic)
.venv/bin/python -m mynes.monitoring.rules
.venv/bin/python -m mynes.core.arp 192.168.1.0/24
.venv/bin/python -m mynes.discovery.mdns
.venv/bin/python -m mynes.integrations.home_assistant

# Docker (host networking is what makes LAN discovery work)
docker compose -f deploy/docker-compose.yml up -d
```

Default port: **5883** (`MYNES_PORT` to change).

## Architecture

```
mynes/
├── paths.py              Paths resolved from the package, not the CWD.
│                         Env overrides: MYNES_HOME/_CONFIG_DIR/_DATA_DIR.
├── core/
│   ├── scanner.py        LANScanner: the orchestrator. scan_network() ->
│   │                     get_devices(). Everything else hangs off this.
│   ├── arp.py            Layer-2 discovery. Raw ARP when privileged, else
│   │                     ping sweep + OS ARP cache. See "Privileges" below.
│   ├── models.py         Unified device model / normalisation
│   ├── network.py        Interface + gateway detection
│   ├── config.py         ConfigManager: config/config.json read/write
│   └── version.py        Git-derived version
├── discovery/            One module per protocol, all optional, all isolated.
│   ├── base.py           DiscoveryBackend + DiscoveredDevice. safe_discover()
│   │                     never raises: a dead protocol yields [] and logs.
│   ├── mdns.py           mDNS/DNS-SD via zeroconf. Matter arrives here too
│   │                     (_matter._tcp / _matterc._udp) — there is no separate
│   │                     Matter stack.
│   ├── ssdp.py           SSDP/UPnP, stdlib sockets only, zero dependencies
│   ├── bluetooth.py      BLE via bleak. Devices keyed by BT address, no IP.
│   └── mqtt.py           Reads Zigbee2MQTT / Z-Wave JS / Tasmota / HA discovery
│                         retained topics — the only way to see radio devices.
├── analysis/             oui, identifier, hostname, advanced, enhanced
├── monitoring/
│   ├── rules.py          PURE functions: (previous, current) -> [Alert].
│   │                     No I/O. Test here first; it is the cheapest layer.
│   ├── notify.py         Channels (stdlib only). Add one = add one function
│   │                     to SENDERS.
│   ├── scheduler.py      One daemon thread: scan -> diff -> alert -> notify
│   └── store.py          Capped JSON alert history + monitor state
├── integrations/
│   ├── home_assistant.py MQTT Discovery push + REST pull/compare
│   └── docker.py         Container/network detection
├── security/             credentials (Fernet + PBKDF2), sanitizer
└── web/
    ├── app.py            Legacy routes + page rendering (large, historic)
    ├── api.py            v2 blueprint: /api/discovery, /monitoring, /alerts,
    │                     /notifications, /integrations, /health, /capabilities
    ├── i18n.py           tr/en translation loader
    ├── templates/        base.html is the shell; pages extend it
    └── static/           design-system.css is the single source of style truth
```

## Conventions

**Never hardcode a colour in a page stylesheet.** `static/css/design-system.css`
defines semantic tokens (`--bg-surface`, `--text-primary`, `--severity-*`) for
light and dark. Page CSS consumes tokens only. Light and dark are both
first-class; the OS preference is the default and `[data-theme]` on `<html>`
overrides it in either direction.

**No emoji as UI icons.** Use the sprite in `templates/_icons.html`:
`<svg class="ds-icon"><use href="#i-network"/></svg>`. Emoji as *content*
(device type labels the user picks) is fine.

**Optional dependencies stay optional.** A missing `bleak` or an unreachable
MQTT broker must degrade that one feature, never break a scan. Follow the
`DiscoveryBackend.available()` pattern: return `(False, "why")` rather than
raising.

**Tell the user why something is missing.** `/api/capabilities` exists because
"it only found two devices" is a permissions problem, not a bug report. New
capability gaps belong there.

**Every non-trivial module carries a runnable `demo()`** with asserts, wired
into `tests/` by a one-line test. No fixtures, no mocks unless unavoidable.

**Turkish and English both matter.** UI strings go through `_()` and
`web/locales/{tr,en}/`. Comments and commit messages are in English; existing
Turkish comments in legacy modules stay.

## Privileges — read this before touching scanning

Raw ARP (`scapy.srp`) requires root. Without it MyNeS falls back to a ping sweep
plus the OS ARP cache, which finds most but not all devices. `core/arp.py`
handles the choice and reports it through `scanner.last_arp_method` and
`scanner.privilege_hint`. **Never let a permission failure return an empty list
silently** — that was a real bug (2 devices reported where 29 existed).

`nmap` is likewise optional: without it, port and service detection is skipped
but discovery still works.

## Security

- `config/config.json` is **tracked in git**. Secrets must never be written
  there. The master password comes from `MYNES_PASSWORD` or
  `config/.master_password` (gitignored, mode 600), auto-generated if absent.
  `tests/test_smoke.py` asserts this.
- Credentials are encrypted with Fernet + PBKDF2-HMAC-SHA256 (100k iterations).
- `security/sanitizer.py` strips sensitive fields before export.
- The scanner is a scanner: only scan networks the user owns.

## Claude Skills in this repo

`.claude/skills/` vendors a curated set (upstream licences alongside them):

- **UI/UX** (from `nextlevelbuilder/ui-ux-pro-max-skill`): `ui-ux-pro-max`,
  `design-system`, `design`, `brand`, `ui-styling`. Load `ui-ux-pro-max` before
  any visual work; its `references/pro-rules.md` is the pre-delivery checklist
  this project's design system was built against.
- **Full-stack** (from `jeffallan/claude-skills`): `python-pro`, `api-designer`,
  `fullstack-guardian`, `code-reviewer`, `security-reviewer`,
  `monitoring-expert`, `test-master`, `websocket-engineer`, `devops-engineer`,
  `playwright-expert`, plus `react-native-expert` and `typescript-pro` for
  Phase 2.

Skill scripts referencing `${CLAUDE_PLUGIN_ROOT}` resolve to the repo root here;
use `.claude/skills/<name>/scripts/...` directly.

## Phase 2

Mobile (React Native + Expo, App Store + Play Store) is planned in
`docs/PHASE2_MOBILE.md`. The server-side prerequisites listed there — token
auth, CORS, QR pairing, a frozen `/api/devices` contract, SSE progress — are
the things to get right in Phase 1 so the client does not force a redesign.
