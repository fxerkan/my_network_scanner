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
│   ├── topology.py       Parent/child uplink tree (traceroute + manual + infra
│   │                     heuristics). See core/subnets.py for the L3 grouping
│   │                     it hangs off, not the same question.
│   ├── subnets.py        Which subnet each device is actually in - a real
│   │                     interface/Docker CIDR when known, else the device's
│   │                     own /24. Feeds the topology/graph subnet overlay.
│   ├── diagnostics.py    On-demand ping/traceroute/port-probe/DNS for one
│   │                     device - thin OS-binary wrappers, parsing kept pure
│   │                     and tested separately from the subprocess calls.
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
│   ├── fingerprint.py    Active service fingerprinting: RTSP/HTTP/SSH/FTP
│   │                     banners + an NBNS (UDP 137) SMB/NetBIOS probe, pure
│   │                     classify()/suggest_name() over the signals gathered.
│   └── os_detect.py      OS family + best-effort WiFi-vs-wired connection-
│                         medium guessing, consolidated from what used to be
│                         three separate, duplicated guessers. Everything here
│                         is a scored guess, never claimed as measured fact.
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
├── platform/             Desktop OS integration. Nothing here runs a
│   ├── privileges.py     privileged command without an explicit --apply.
│   │                     Linux setcap / macOS ChmodBPF+access_bpf / Win Npcap.
│   ├── service.py        launchd LaunchAgent | systemd --user | Scheduled Task.
│   │                     All USER-level: no sudo, uninstall = delete one file.
│   └── files/            ChmodBPF script + its LaunchDaemon plist
├── tray.py               pystray menu bar / notification area icon (optional)
├── security/             credentials (Fernet + PBKDF2), sanitizer
│   └── cve.py            Curated CVE-pattern table (real CVE IDs, banner-
│                         anchored regexes) + port-based attack-surface
│                         exposures, matched against a device's already-
│                         collected fingerprint. Deliberately not a live
│                         NVD/vulners feed - see the module docstring.
└── web/
    ├── app.py            Legacy routes + page rendering (large, historic)
    ├── api.py            v2 blueprint: /api/discovery, /monitoring, /alerts,
    │                     /notifications, /integrations, /health, /capabilities,
    │                     /topology, /subnets, /diagnostics/<ip>/*,
    │                     /security/vulnerabilities[/<ip>]
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

`platform/privileges.py` offers the narrow, permanent fix per OS instead of
"run everything as root" — a web app parsing network input should not be root.
It prints commands by default and only executes them on `--apply`, so the OS
password prompt appears in the user's own terminal. **A web request must never
be able to escalate privileges silently.**

Two traps already hit and fixed here, do not reintroduce them:

- `service.py` must launch `sys.executable`, **not** `os.path.realpath(...)`.
  Resolving a venv's `bin/python` lands on the base interpreter where `mynes`
  is not installed, and the service exits 1 on every start.
- `launchctl list` exits 0 for a job that is loaded but dead, and `unload`
  returns before the child is gone. Status is read from the PID field, and
  uninstall waits for the process to actually exit — otherwise an orphan keeps
  holding port 5883.

## Configuration

`.env` in the repo root is loaded by `mynes/__init__.py`, so every entry point
picks it up - the web app, `python -m mynes`, the tray icon and standalone
scripts alike. Real environment variables always win over the file. `.env` is
gitignored; never commit it.

Home Assistant credentials come from `HA_URL` / `HA_TOKEN`.

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

## Versioning

SemVer, GitHub-standard, but **scope-driven, not commit-triggered**. PATCH is
the floor; MINOR and MAJOR are earned, not tripped by a keyword. This is a hard
rule for every contributor, human or agent — apply it identically:

- **PATCH** (`1.4.1` → `1.4.2` → … → `1.4.12`) — the **default for almost
  everything that ships**: bug fixes, small features, UI tweaks, refactors,
  perf, a new tool or two. When in doubt, it is a patch. Patches accumulate;
  there is nothing wrong with `1.4.19`.
- **MINOR** (`1.4.x` → `1.5.0`) — **opt-in only**, for a genuine milestone: a
  whole new subsystem or discovery protocol, a redesigned page, a feature set
  a user would notice as "a new thing." A single `feat:` commit is **not**
  automatically a minor. You must pass `--minor` and mean it.
- **MAJOR** (`1.x` → `2.0.0`) — a breaking, root change: an incompatible config
  or API shape the user must react to. Auto-detected from `feat!:` / `fix!:` /
  a `BREAKING CHANGE:` trailer (never silent) or forced with `--major`. Rare.

Rule of thumb for the minor call: could you write a one-line release headline a
user would care about? Then `--minor`. Otherwise `--patch`. Ten small features
in a row are ten patches, not one minor — unless together they form a milestone
worth announcing, and then it's a deliberate `--minor`, once.

**A change that never reaches a user's install is not a release.** `docs/`,
`deploy/`, `tests/`, `.github/` and the top-level markdown are outside the
package; a README typo is not a version bump. Only `mynes/`, `config/`,
`scripts/` and `pyproject.toml` count.

```bash
python scripts/release_bump.py            # preview — defaults to a PATCH bump
python scripts/release_bump.py --minor    # cut a milestone instead
python scripts/release_bump.py --apply    # write it to pyproject + version.py
```

## Phase 2

Mobile (React Native + Expo, App Store + Play Store) is planned in
`docs/PHASE2_MOBILE.md`. The server-side prerequisites listed there — token
auth, CORS, QR pairing, a frozen `/api/devices` contract, SSE progress — are
the things to get right in Phase 1 so the client does not force a redesign.
