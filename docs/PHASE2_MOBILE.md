# Phase 2 — MyNeS Mobile (iOS, Android, tablet, TV)

Phase 1 turned MyNeS into a proper product on the web: a design system, a PWA,
scheduled monitoring with push-capable alerts, and a JSON API that is already
client-agnostic. Phase 2 puts a native app on the App Store and Google Play on
top of that same API.

This document is the plan, not the implementation. It exists so the Phase-1 API
does not drift away from what Phase 2 will need.

---

## 1. Decision: what to build

| Option | Verdict |
|---|---|
| **React Native + Expo** | **Chosen.** One codebase for iOS, iPadOS, Android, Android tablets and Android TV / Fire TV. EAS Build removes the need for a Mac in CI. Expo Router gives file-based navigation. Push via `expo-notifications` works on both stores. |
| Flutter | Equally capable, but adds a second language to a Python + JS repo and its TV story is weaker. |
| PWA only | Already shipped in Phase 1 and genuinely good on Android. Rejected as the *only* answer because iOS restricts background push for web apps, and the stores were an explicit requirement. |
| Native (Swift + Kotlin) | Best per-platform polish, roughly triple the work. Not justified for a LAN dashboard. |

The PWA stays. It is the zero-install path and the desktop path; the native app
is the store path and the push path.

---

## 2. Architecture

```
                     ┌───────────────────────────┐
                     │   MyNeS server (Phase 1)   │
                     │   Flask + scanner + rules  │
                     └────────────┬──────────────┘
                                  │ JSON over HTTP (LAN)
                ┌─────────────────┼─────────────────┐
                │                 │                 │
        ┌───────▼──────┐  ┌───────▼──────┐  ┌──────▼───────┐
        │  PWA (web)   │  │ React Native │  │ Home Assistant│
        │  Phase 1     │  │   Phase 2    │  │  MQTT / REST  │
        └──────────────┘  └───────┬──────┘  └───────────────┘
                                  │
                          ┌───────▼────────┐
                          │ Expo Push (FCM │
                          │  / APNs) relay │
                          └────────────────┘
```

The phone talks to the server directly on the LAN. Nothing about a home network
scan should leave the house, so there is no MyNeS cloud in this design.

### The one piece that needs a relay

Push notifications require APNs/FCM, which a LAN-only server cannot reach
without a public endpoint. Three options, in preference order:

1. **Local-first (default).** The app polls `/api/health` while in the
   foreground, and the *server* pushes to a user-chosen channel (ntfy, Telegram,
   webhook) for background alerts. Those channels already exist in Phase 1 and
   already deliver to phones. No relay, no accounts, no privacy question.
2. **Self-hosted relay (opt-in).** The server posts alerts to an Expo push token
   through the user's own reverse proxy or Tailscale/Cloudflare tunnel.
3. **Hosted relay (opt-in, later).** A thin Anthropic-of-nothing service that
   only forwards `{token, title, body}`. Only if users ask; it introduces the
   privacy surface options 1 and 2 avoid.

Ship with option 1. It covers the requirement — "get notified when a device goes
offline" — with no infrastructure.

---

## 3. Server work required in Phase 1's API

These are the gaps the mobile app will hit. Each is small and belongs in the
Flask app, not the client.

| Gap | Why | Status |
|---|---|---|
| `GET /api/health` | Connection check + unread badge | **Done** |
| Token auth (`Authorization: Bearer`) | The web UI relies on a same-origin session; a native app needs a token | **To do** |
| CORS allow-list | The app runs from a non-web origin | **To do** |
| Pairing flow (server shows a QR containing `{url, token}`) | Typing a LAN IP and a token on a phone is miserable | **To do** |
| `GET /api/devices` normalised payload | The legacy `/get_devices` returns the internal model; the app wants a stable contract | **To do** |
| Server-Sent Events for scan progress | The web UI polls `/progress`; SSE saves battery on mobile | **To do** |
| `POST /api/push/register` | Store an Expo token per device when the relay is enabled | Optional (needs relay) |

**API contract to freeze before writing the client:**

```jsonc
// GET /api/devices
{
  "devices": [{
    "id": "mac:aa:bb:cc:dd:ee:ff",     // stable identity
    "ip": "192.168.1.42",
    "mac": "aa:bb:cc:dd:ee:ff",
    "name": "Living room Pi",
    "vendor": "Raspberry Pi Foundation",
    "device_type": "Single-board computer",
    "status": "online",                 // online | offline
    "last_seen": "2026-08-03T18:20:00Z",
    "open_ports": [22, 80],
    "services": ["SSH", "HTTP"],
    "discovery_sources": ["arp", "mdns"],
    "attributes": {}
  }],
  "generated_at": "2026-08-03T18:20:05Z"
}
```

---

## 4. App structure

```
mobile/
├── app.json                  # Expo config: bundle ids, icons, splash, TV flags
├── eas.json                  # build profiles: development / preview / production
├── app/                      # expo-router file-based routes
│   ├── _layout.tsx           # tab navigator, theme provider
│   ├── index.tsx             # Devices  (list + search + filters)
│   ├── device/[id].tsx       # Device detail, ports, history, actions
│   ├── discovery.tsx         # Protocol sweep (mDNS/SSDP/BLE/MQTT)
│   ├── alerts.tsx            # Alert feed + schedule controls
│   └── settings.tsx          # Server pairing, theme, notification channels
├── src/
│   ├── api/                  # typed client generated from the contract above
│   ├── theme/                # the SAME tokens as design-system.css
│   ├── components/           # DeviceCard, StatTile, Badge, EmptyState, ...
│   └── store/                # TanStack Query + MMKV persistence
└── assets/
```

**Design parity is a hard requirement.** `src/theme/tokens.ts` is generated from
`mynes/web/static/css/design-system.css` so that a colour changed in one place
changes in both. A small script in `scripts/` does the extraction; the CSS stays
the source of truth.

---

## 5. Platform matrix

| Target | How | Notes |
|---|---|---|
| iPhone | Expo → App Store | Min iOS 15. Uses `expo-network` for LAN discovery hints. |
| iPad | Same binary | Two-column layout at `≥768pt`; the device list becomes a master-detail split. |
| Android phone | Expo → Play Store | Min API 24. |
| Android tablet | Same binary | Same split layout. |
| Android TV / Fire TV | Expo TV variant (`@react-native-tv/config-tv`) | D-pad focus only. Reuses the same spatial-navigation model already in the web UI. |
| Apple TV | Expo TV variant | Lower priority: home-lab users overwhelmingly have Android-based TVs. |

TV builds ship in the *second* store release, not the first. Getting phone and
tablet right is the gate.

---

## 6. Store readiness checklist

Both stores reject network-scanning apps that look like attack tools. The
framing matters as much as the code.

**Apple**
- [ ] `NSLocalNetworkUsageDescription` — explain LAN scanning in plain language
- [ ] `NSBluetoothAlwaysUsageDescription` — required for the BLE view
- [ ] `NSBonjourServices` — declare every mDNS service type the app browses
- [ ] Privacy manifest (`PrivacyInfo.xcprivacy`) — declare *no* data collection
- [ ] Review notes: "connects only to a server the user runs on their own
      network; scans only the user's own LAN; no data leaves the device"
- [ ] Demo server reachable for the reviewer, or a recorded walkthrough

**Google Play**
- [ ] `ACCESS_FINE_LOCATION` justification for BLE scanning on Android ≤ 11,
      or `neverForLocation` on `BLUETOOTH_SCAN` for Android 12+ (preferred)
- [ ] Data safety form: no collection, no sharing
- [ ] Target the current API level
- [ ] Avoid `QUERY_ALL_PACKAGES` entirely

**Both**
- [ ] Privacy policy URL (the repo can host it on GitHub Pages)
- [ ] Screenshots for phone, 7" tablet, 10" tablet (and TV in release 2)
- [ ] The app must be usable with no server configured — a clear pairing screen,
      not a crash or an empty list

---

## 7. Milestones

| # | Deliverable | Depends on |
|---|---|---|
| M1 | Token auth + CORS + QR pairing on the server; `/api/devices` contract frozen | — |
| M2 | Expo skeleton, theme tokens generated from CSS, pairing screen, device list | M1 |
| M3 | Device detail, search/filter, pull-to-refresh, offline cache | M2 |
| M4 | Discovery screen (mDNS/SSDP/MQTT via server; BLE via the phone's own radio) | M2 |
| M5 | Alerts screen + local notifications + ntfy deep links | M2 |
| M6 | Tablet layouts, accessibility pass, i18n (tr/en) shared with the web locales | M3–M5 |
| M7 | Store assets, privacy policy, TestFlight + internal testing track | M6 |
| M8 | Public release; TV variant begins | M7 |

M1 is server-side and could land at the end of Phase 1 — doing so lets M2 start
without touching Python again.

---

## 8. Open questions

1. **BLE on the phone vs. on the server.** The phone's own radio sees different
   devices than the server's. Showing both is more honest, but the merge UI
   needs care to avoid looking like duplicates.
2. **Multiple servers.** Users with more than one site (home + parents' house)
   will want a server switcher. Cheap to design for now, expensive to retrofit.
3. **Write actions.** Should the app be able to trigger a scan and edit device
   aliases, or stay read-only in v1? Read-only ships faster and avoids most of
   the auth surface.
