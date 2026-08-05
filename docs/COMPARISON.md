# MyNeS vs. the alternatives

What MyNeS actually is next to Fing, Angry IP Scanner, Advanced IP Scanner, NetAlertX and
nmap — honestly, including where it loses — plus the ready-to-paste copy for AlternativeTo
and the other directories.

Companion documents: [`PUBLISHING.md`](PUBLISHING.md) (app-store submissions),
[`OUTREACH.md`](OUTREACH.md) (Reddit/forum copy). This file is the source of truth for
*claims*; if a number or a feature changes here, fix it there too.

Version this was written against: **v1.5.0**.

---

## 1. The one-sentence position

> **Self-hosted Fing that also sees the devices that have no IP address.**

That is the whole pitch. Two halves, both load-bearing:

- **Self-hosted** — no account, no cloud, no telemetry, AGPL-3.0, runs in a container on the
  Pi you already own. This is what wins on r/selfhosted and in the app stores.
- **No IP address** — Bluetooth LE, Zigbee and Z-Wave devices are invisible to every scanner
  in this comparison, because they are not on the IP network at all. MyNeS reads them over
  BLE advertisements and the Zigbee2MQTT / Z-Wave JS retained MQTT topics. In a 2026 smart
  home that is often a third of the devices in the house.

Everything else — the five views, the alerting, the Home Assistant integration — is
supporting evidence, not the headline.

---

## 2. The matrix

| | **MyNeS** | **Fing** | **Angry IP Scanner** | **Advanced IP Scanner** | **NetAlertX** | **nmap / Zenmap** |
|---|---|---|---|---|---|---|
| License | AGPL-3.0 | Proprietary | GPL-2.0 | Proprietary (freeware) | GPL-3.0 | NPSL |
| Cost | Free | Free app, paid Fingbox hardware / premium tiers | Free | Free | Free | Free |
| Account required | No | Yes for most of the useful features | No | No | No | No |
| Cloud / telemetry | None | Yes, central to the product | None | Phones home for updates | None | None |
| Runs as | Self-hosted web app | Mobile + desktop app + hardware | Desktop app | Windows desktop | Self-hosted web app | CLI (+ Zenmap GUI) |
| Platforms | Linux / macOS / Windows / Docker / Pi | iOS, Android, macOS, Windows | Any (Java) | Windows only | Linux / Docker / Pi | Everything |
| ARP layer-2 discovery | Yes (raw ARP, ping-sweep fallback) | Yes | Ping + port only | Yes | Yes | Yes |
| Port / service detection | Yes (via nmap, optional) | Yes | Basic port list | Basic | Via nmap | Best in class |
| mDNS / Bonjour, SSDP/UPnP | Yes | Yes | No | Partial | Partial | Scripted |
| Matter | Yes (`_matter._tcp` over mDNS) | Partial | No | No | No | No |
| **Bluetooth LE** | **Yes** | Partial (mobile app only) | No | No | No | No |
| **Zigbee / Z-Wave (via MQTT)** | **Yes** | No | No | No | No | No |
| Docker containers & networks | Yes | No | No | No | No | No |
| Continuous monitoring + alerts | Yes (new device, offline, IP change, MAC change, new port) | Yes, mostly on Fingbox / premium | No | No | Yes — its core feature | No |
| Notification channels | Webhook, e-mail, Telegram, Discord, Slack, ntfy, MQTT | Push, e-mail | — | — | Many | — |
| History / change log | Yes | Yes (cloud) | No | No | Yes | No |
| Home Assistant integration | Yes — MQTT Discovery push + REST pull | No | No | No | Community add-on | No |
| Views | Card, table, **graph, topology, floor plan** | List | List | List | List | Topology in Zenmap |
| Manual device editing / naming | Yes, with backup + restore as JSON | Yes (cloud-bound) | No | No | Yes | No |
| Web API | Yes (`/api/*`, `/api/capabilities`) | Private | No | No | Yes | XML output |
| Localisation | Turkish + English | Many | Many | Many | Many | Many |
| PWA / installable on phone | Yes | Native apps | No | No | Yes | No |
| Maturity | Young (2025–), one maintainer | ~15 years, a company | ~20 years | ~15 years | Several years, active | ~25 years |

Notes on reading this table: "Partial" means the capability exists in some editions or
platforms but not reliably across the product. Nothing here is a benchmark result — it is a
feature comparison, and feature comparisons age. Re-check before a submission round.

---

## 3. Head to head

### vs. Fing — *the one that matters*

Fing is the reference point. Nearly everyone who finds MyNeS is searching for "self-hosted
Fing", so the comparison is written to that.

**Where MyNeS wins**

- No account, no cloud, no data leaving the LAN. Fing's device inventory lives on their
  servers; that is a non-starter for the self-hosted audience and increasingly for anyone.
- Free forever, AGPL-3.0. Fing's genuinely interesting monitoring is gated behind Fingbox
  hardware or a subscription.
- BLE + Zigbee + Z-Wave. Fing scans IP. Your Zigbee bulbs simply do not appear.
- Home Assistant is a first-class target, not an afterthought — MQTT Discovery means every
  device shows up as an HA entity with no glue code.
- Docker container and virtual-network awareness, including container-to-host nesting.
- Runs headless on hardware you already have; the UI is a web app, so any device on the LAN
  can open it.
- Turkish UI. Small, but Fing's Turkish is thin and this is a real differentiator locally.

**Where Fing wins**

- Polish. Fifteen years and a paid team versus one maintainer. Their mobile apps are better
  than a PWA, and it shows.
- Device identification. Fing's fingerprint database is enormous and crowdsourced from
  millions of installs. MyNeS uses OUI + hostname + service heuristics and will lose on
  obscure hardware. This is the single biggest honest gap.
- Internet speed test, ISP outage detection, WAN-side tooling — MyNeS does none of it.
- Fingbox gives you real network-level blocking and bandwidth analysis. MyNeS observes; it
  does not enforce.
- Install effort: Fing is one tap. MyNeS is a container, host networking and a capability
  discussion.

### vs. Angry IP Scanner

Different tool for a different job, and it is worth saying so plainly rather than pretending
to compete.

**Where MyNeS wins:** Angry IP is a stateless one-shot scanner. It has no history, no
monitoring, no alerting, no device naming, no persistence between runs, and no discovery
beyond ping and TCP connect. Anything on this list that isn't "scan a range now" is out of
scope for it.

**Where Angry IP wins:** it is a 4 MB download that starts instantly, needs no server, no
container and no Python, and it is genuinely fast on a wide range. If someone just wants to
know which IPs are up right now, recommend it — that honesty is what makes the rest of the
comparison credible.

### vs. Advanced IP Scanner

**Where MyNeS wins:** cross-platform (Advanced IP Scanner is Windows-only), open source,
continuous monitoring, protocol discovery beyond ARP/NetBIOS, no proprietary binary phoning
home on a network-management tool.

**Where Advanced IP Scanner wins:** on Windows, its remote-control integration (RDP,
Radmin, shared-folder browsing, remote wake/shutdown) is real, useful and completely absent
from MyNeS. Zero-install portable mode. It is the pragmatic choice on a Windows-only LAN.

### vs. NetAlertX (formerly Pi.Alert) — *the closest thing to a direct competitor*

Same shape: self-hosted, containerised, web UI, presence monitoring and notifications. Be
respectful here — this is a good project and its users overlap almost perfectly with the
target audience.

**Where MyNeS wins:** non-IP discovery (BLE, Zigbee/Z-Wave over MQTT, Matter) is the clear
differentiator. Plus the graph / topology / floor-plan views, native Home Assistant MQTT
Discovery, container awareness, and `/api/capabilities` telling you *why* a scan found less
than it should have.

**Where NetAlertX wins:** more mature, more contributors, longer track record on presence
detection specifically, and a wider set of plugins and notification integrations. If someone
only needs "tell me when an unknown device joins", it is an excellent and battle-tested
answer.

### vs. nmap / Zenmap

Not a competitor — a dependency. MyNeS shells out to nmap for port and service detection and
degrades gracefully when it is absent. The comparison is only worth making because people
search for scanner alternatives on the nmap AlternativeTo page: MyNeS is the friendly,
persistent, always-on layer over a scan; nmap is the deep instrument you reach for when you
need to know exactly what is on port 8443.

---

## 4. The honest weaknesses (say these before someone else does)

Naming these in the announcement is what makes the rest believable, and it pre-empts the
first critical comment.

1. **Young project, one maintainer.** No decade of hardening behind it.
2. **Device fingerprinting is weaker than Fing's.** OUI + hostname + open ports + mDNS
   service names. No crowdsourced database. Unknown devices stay unknown more often.
3. **Needs privileges to be at its best.** Raw ARP needs `NET_RAW`/root, and Docker needs
   host networking. Without them it falls back to a ping sweep plus the ARP cache and finds
   fewer devices. It tells you so — that is what `/api/capabilities` is for — but it is
   friction.
4. **Web UI login is optional and off by default.** Fine on a trusted LAN, which is the
   documented deployment, but there is no bearer-token API auth yet — that is Phase 2 work
   for the mobile app. Do not expose it to the internet.
5. **Python/Flask, not a compiled binary.** On a `/16` or a several-hundred-device network a
   full scan is minutes, not seconds. Designed for a home LAN, not a campus.
6. **No mobile app yet.** A PWA installs on a phone and works, but it is not a native app.
   React Native is planned ([`PHASE2_MOBILE.md`](PHASE2_MOBILE.md)); do not announce it as if
   it exists.
7. **MQTT-dependent for radio devices.** Zigbee and Z-Wave visibility requires an existing
   Zigbee2MQTT / Z-Wave JS broker. MyNeS reads their retained topics; it does not talk to a
   Zigbee radio itself. Without a broker, that headline feature is unavailable.
8. **UI is Turkish and English only.**

---

## 5. AlternativeTo submission

### Which pages to add MyNeS to

Ranked by expected traffic and fit. Add it as an alternative on each; each one is a separate
short form.

| Page | Fit | Note |
|---|---|---|
| [Fing](https://alternativeto.net/software/fing/) | Perfect | The one that matters. Six pages of existing alternatives = steady traffic. |
| [Fingbox](https://alternativeto.net/software/fingbox) | Good | Hardware page, but the "I don't want to buy a box" audience lands here. |
| [Advanced IP Scanner](https://alternativeto.net/software/advanced-ip-scanner/) | Good | Large Windows audience looking for cross-platform. |
| [Angry IP Scanner](https://alternativeto.net/software/angry-ip-scanner/) | Good | Open-source-minded audience. |
| [Nmap](https://alternativeto.net/software/nmap/) | Moderate | High traffic, weaker fit — position as the GUI/monitoring layer, not as a replacement. |
| [Pi.Alert / NetAlertX](https://alternativeto.net/software/pi-alert/) | Good | Direct overlap, exactly the right audience. |
| [Wireless Network Watcher](https://alternativeto.net/software/wireless-network-watcher/) | Moderate | Same job, much smaller tool. |
| [GlassWire](https://alternativeto.net/software/glasswire/) | Weak | Skip unless the others are done. Different problem (per-app traffic). |

Create the MyNeS product page **first**, then add it as an alternative from each page above —
otherwise every submission creates a duplicate draft.

### Product page fields (paste these)

**Name:** `MyNeS (My Network Scanner)`

**Tagline (≤ 60 chars):**

```
Your family's friendly network scanner
```

**Short description (≤ 160 chars):**

```
Self-hosted network scanner that finds every device on your LAN — including the Bluetooth, Zigbee and Z-Wave ones an IP scan cannot see.
```

**Full description:**

```
MyNeS (My Network Scanner) is a self-hosted, open-source network scanner and monitor for
home labs and smart homes. It discovers, identifies and watches every device on your local
network from a modern web interface — with no account, no cloud and no telemetry.

Unlike an IP scanner, MyNeS also finds the devices that have no IP address. Alongside ARP
and port scanning it reads mDNS/Bonjour, Matter, SSDP/UPnP, Bluetooth LE, and the
Zigbee2MQTT / Z-Wave JS / Tasmota MQTT topics — so the Zigbee bulbs and BLE sensors that are
invisible to Fing or Angry IP Scanner show up next to your laptops and cameras.

Features:
• Automatic network detection, ARP discovery and 1000+ port service detection
• Multi-protocol discovery: mDNS, Matter, SSDP/UPnP, Bluetooth LE, MQTT (Zigbee/Z-Wave)
• Docker container and virtual-network awareness
• Continuous monitoring with alerts: new device, device offline, IP change, MAC change
  (ARP spoofing), newly opened port
• Notifications via webhook, e-mail, Telegram, Discord, Slack, ntfy and MQTT
• Home Assistant integration — MQTT Discovery push and REST pull
• Five views: card, table, graph, network topology and drag-and-drop floor plan
• Manual device editing, JSON backup and restore, scan history and statistics
• PWA — installable on a phone or tablet, light and dark themes, responsive from 320px up
• Turkish and English interface

Runs on Linux, macOS, Windows, Docker and Raspberry Pi. AGPL-3.0.
```

**Licence:** `Open Source` — `AGPL-3.0`
**Platforms:** `Linux`, `Mac`, `Windows`, `Self-Hosted`, `Docker`, `Web-Based`, `PWA`
**Categories:** `Network & Admin`, `Security & Privacy`, `System & Hardware`, `Home Automation`
**Website:** `https://github.com/fxerkan/my_network_scanner`
**Source:** `https://github.com/fxerkan/my_network_scanner`
**Docker:** `https://hub.docker.com/r/fxerkan/my_network_scanner`
**Icon:** `assets/icon.png` (256×256, produced by `scripts/make_store_assets.py`)
**Screenshots:** `assets/store/1.jpg`, `2.jpg`, `3.jpg` (1920×1080)

**Tags:**

```
network-scanner, network-monitoring, self-hosted, lan-scanner, device-discovery,
home-assistant, smart-home, iot, bluetooth-le, zigbee, z-wave, mdns, upnp, docker,
raspberry-pi, homelab, open-source, privacy, no-cloud, arp-scanner
```

### The "why it's an alternative" comment

AlternativeTo lets you add a sentence explaining the relationship. Vary it per page — the
same paragraph on six pages reads as spam.

**On the Fing page:**

```
Self-hosted and open source, so nothing leaves your LAN and there is no account. Covers the
same ground — device discovery, naming, new-device alerts — and adds Bluetooth LE, Zigbee and
Z-Wave (via MQTT) discovery plus a native Home Assistant integration. No speed test or
WAN-side tooling, and its device fingerprint database is smaller than Fing's.
```

**On the Angry IP Scanner page:**

```
Where Angry IP is a fast one-shot scanner, MyNeS keeps state: scan history, per-device
naming and notes, continuous monitoring with alerts, and discovery beyond ping/TCP (mDNS,
SSDP, Matter, Bluetooth LE, Zigbee/Z-Wave). It is a self-hosted web app rather than a
desktop tool, so it is heavier to set up but always on.
```

**On the Advanced IP Scanner page:**

```
Cross-platform and open source rather than Windows-only, with continuous monitoring and
alerting on top of scanning. No RDP/Radmin remote-control integration — this one watches the
network rather than administering the machines on it.
```

**On the NetAlertX / Pi.Alert page:**

```
Same idea — self-hosted device discovery and presence monitoring in a container — with
non-IP discovery added: Bluetooth LE, Matter, and Zigbee/Z-Wave read from Zigbee2MQTT or
Z-Wave JS over MQTT. Also ships graph, topology and floor-plan views and pushes devices into
Home Assistant via MQTT Discovery.
```

**On the Nmap page:**

```
Not a replacement for nmap — MyNeS uses nmap for port and service detection. It is the
always-on, self-hosted web layer around it: continuous scanning, device naming and history,
alerts, and discovery protocols nmap does not cover (Bluetooth LE, Zigbee/Z-Wave, Matter).
```

---

## 6. Blurbs at other lengths

For Product Hunt, awesome-lists, GitHub topics, Docker Hub, Twitter/Mastodon and the app
stores. Reuse these verbatim so the positioning stays identical everywhere.

**50 chars (GitHub repo description prefix, app-store tile):**

```
Self-hosted network scanner for the smart home
```

**100 chars:**

```
Self-hosted LAN scanner that also sees Bluetooth, Zigbee and Z-Wave devices. No cloud, no account.
```

**280 chars (Mastodon / Twitter / Product Hunt tagline):**

```
MyNeS is a self-hosted network scanner for home labs: finds every device on your LAN, and
also the ones an IP scan can't see — Bluetooth LE, Zigbee, Z-Wave, Matter. Alerts on new or
missing devices, pushes them into Home Assistant. No cloud, no account. AGPL-3.0.
```

**One-paragraph (awesome-list entry):**

```
[MyNeS](https://github.com/fxerkan/my_network_scanner) — Self-hosted network scanner and
monitor. Discovers devices over ARP, mDNS, SSDP/UPnP, Matter, Bluetooth LE and MQTT
(Zigbee2MQTT / Z-Wave JS), so it sees the devices an IP scan cannot. Continuous monitoring
with alerts, Home Assistant MQTT Discovery integration, graph/topology/floor-plan views.
`AGPL-3.0` `Python/Docker`
```

---

## 7. Claim discipline

Rules for every announcement, review reply and directory entry. Breaking one of these turns a
comparison into a fight.

- **Never say a competitor is bad.** Say what MyNeS does differently. "Fing is cloud-based"
  is a fact; "Fing spies on you" is a lawsuit and a flame war.
- **Never claim a feature that needs a dependency without naming the dependency.** Zigbee
  visibility requires an MQTT broker. Say so in the same sentence, every time.
- **Never compare on speed.** There is no benchmark. Do not imply one.
- **Never say "better than".** Say "different from", and list the trade-off.
- **Lead with the weakness in author posts.** Disclose authorship, then name one honest gap.
  It converts better than a feature list and it is the rule on r/selfhosted anyway.
- **Do not announce Phase 2 as shipped.** The mobile app does not exist yet.
- **Re-verify this file before each submission round.** Competitor products change; a stale
  matrix is the fastest way to lose credibility on a comparison page.
