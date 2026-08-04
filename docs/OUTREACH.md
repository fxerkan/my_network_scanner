# MyNeS community outreach kit

Ready-to-paste copy for Reddit, forums and directories, plus the rules that keep it from
reading as spam.

> **A note on the links you gave me.** The r/homelab thread you linked
> ([12udm7n](https://www.reddit.com/r/homelab/comments/12udm7n/), ~April 2023) is someone asking
> *"is there an app-store-like thing for self-hosted software"* — the answers are CasaOS, Umbrel,
> Yacht, Portainer. That is a **distribution research** link, not an outreach target: replying
> there with a network scanner would be off-topic on a two-year-old thread. It belongs in
> [`PUBLISHING.md`](PUBLISHING.md), which is where I used it. The live-thread hunting below has to
> be done from the search URLs, because Reddit blocks automated fetching — every URL in §2 is a
> search you click, not a thread I found for you.

---

## 1. The rules (read once, then never break them)

1. **Disclose every time.** Open with *"I built this"* or *"disclaimer: I'm the author"*. On
   r/selfhosted and r/homelab, an undisclosed plug gets you banned; a disclosed one gets upvoted.
2. **Answer the question first, mention MyNeS second.** If someone asks "how do I find what's on
   my LAN", the reply leads with the answer (`arp-scan`, their router's DHCP table, Fing) and
   *then* says what MyNeS adds. A reply that is only a link is removed.
3. **Never reply to a thread older than ~6 months.** Necroposting is the fastest way to get
   flagged.
4. **Cap it at ~2 self-promo comments a day**, and keep a real comment-to-plug ratio of at least
   10:1. Participate in threads you have nothing to sell in.
5. **Read each subreddit's self-promo rule before the first post.** r/homelab and r/selfhosted
   both allow author posts; r/HomeNetworking is stricter; r/homeassistant wants a working HA
   integration, not a teaser.
6. **Post the launch thread once per subreddit, ever.** Version 2.0 earns a second one; a point
   release does not.
7. **Never post a screenshot with your real MACs, hostnames or SSIDs in it.** Use the sanitised
   ones in `assets/screenshots/` — `security/sanitizer.py` exists for exactly this reason, and a
   leaked home-lab inventory is a genuinely bad day.

---

## 2. Where to hunt — click these searches weekly

Reddit's own search, scoped and sorted by new. Bookmark them; run them once a week.

**"Help me see what's on my network"**
- <https://www.reddit.com/r/homelab/search/?q=%22what%20devices%20are%20on%20my%20network%22&restrict_sr=1&sort=new>
- <https://www.reddit.com/r/HomeNetworking/search/?q=%22unknown%20device%22%20network&restrict_sr=1&sort=new>
- <https://www.reddit.com/r/selfhosted/search/?q=network%20scanner&restrict_sr=1&sort=new>

**"Fing alternative / self-hosted Fing"** — your single highest-conversion query
- <https://www.reddit.com/r/selfhosted/search/?q=fing&restrict_sr=1&sort=new>
- <https://www.reddit.com/r/homelab/search/?q=fing%20alternative&restrict_sr=1&sort=new>
- <https://www.reddit.com/search/?q=%22self-hosted%20fing%22&sort=new>

**"Device inventory / IPAM but simpler than NetBox"**
- <https://www.reddit.com/r/homelab/search/?q=netbox%20overkill&restrict_sr=1&sort=new>
- <https://www.reddit.com/r/selfhosted/search/?q=%22device%20inventory%22&restrict_sr=1&sort=new>

**Home Assistant presence / device tracking**
- <https://www.reddit.com/r/homeassistant/search/?q=device_tracker%20ping%20unreliable&restrict_sr=1&sort=new>
- <https://www.reddit.com/r/homeassistant/search/?q=%22what%20is%20this%20device%22&restrict_sr=1&sort=new>

**Zigbee / Z-Wave / Matter inventory**
- <https://www.reddit.com/r/homeassistant/search/?q=zigbee2mqtt%20inventory&restrict_sr=1&sort=new>
- <https://www.reddit.com/r/smarthome/search/?q=%22how%20many%20devices%22%20inventory&restrict_sr=1&sort=new>

**New-device alerting / "is someone on my Wi-Fi"**
- <https://www.reddit.com/r/HomeNetworking/search/?q=alert%20new%20device%20joined&restrict_sr=1&sort=new>
- <https://www.reddit.com/r/homelab/search/?q=%22new%20device%22%20notification&restrict_sr=1&sort=new>

Beyond Reddit, the same weekly sweep:

| Place | What to watch |
|-------|---------------|
| [r/selfhosted weekly "What did you host this week?"](https://www.reddit.com/r/selfhosted/) | The one place a plug is always welcome. Post there first. |
| [Home Assistant Community forum](https://community.home-assistant.io/) | Search "device tracker unreliable", "network inventory". |
| [Unraid forums](https://forums.unraid.net/) | Your Unraid CA support thread doubles as an outreach channel. |
| [lemmy.world/c/selfhosted](https://lemmy.world/c/selfhosted) | Smaller, friendlier, indexes well. |
| [Hacker News "Show HN"](https://news.ycombinator.com/show) | One shot. See §4. |
| [selfh.st weekly newsletter](https://selfh.st/) | Submit once; they cover new self-hosted releases. |
| [AlternativeTo — Fing page](https://alternativeto.net/software/fing/) | Add MyNeS as an alternative. Fing has six pages of alternatives and steady traffic; this is free, permanent, and search-engine visible. Do the same on the [Nmap](https://alternativeto.net/software/nmap/) and [Fingbox](https://alternativeto.net/software/fingbox) pages. |
| [awesome.casaos.io](https://awesome.casaos.io/) + awesome-lists | See [`PUBLISHING.md` §10](PUBLISHING.md). |

---

## 3. Reply templates by thread archetype

Swap the bracketed bits. Never paste one unedited — mirror the asker's own words back at them.

### A. "What's this unknown device on my network?"

> Your router's DHCP lease table plus `arp-scan -l` will get you the MAC, and the first three
> octets tell you the vendor — that alone usually solves it.
>
> If it keeps happening, disclaimer: I wrote a self-hosted tool for this called MyNeS. It does the
> ARP sweep but also listens on mDNS/Bonjour and SSDP, so instead of `a4:cf:12:xx:xx:xx —
> Espressif` you often get the actual advertised name and service list, which is usually enough
> to recognise the thing. MIT, runs in Docker, no cloud:
> https://github.com/fxerkan/my_network_scanner

### B. "Is there a self-hosted Fing?"

> Disclaimer: I'm the author of one — MyNeS. It's the itch I had too: Fing wants an account and a
> phone, and I wanted something that lives on the home server.
>
> Where it goes past Fing: it also reads mDNS/SSDP/Matter, Bluetooth LE, and MQTT — so the Zigbee
> bulbs behind Zigbee2MQTT and the Z-Wave sensors behind Z-Wave JS show up in the same inventory
> as the laptops, even though they have no IP at all. Plus scan history, alerts when something new
> appears, and two-way Home Assistant integration.
>
> MIT licensed, Docker image is multi-arch so it runs fine on a Pi:
> https://github.com/fxerkan/my_network_scanner — happy to hear what's missing.

### C. "NetBox is overkill for my home lab"

> Agreed, NetBox is built for people who need to model a datacentre.
>
> Disclosure, I built MyNeS for the other end of that spectrum: it discovers devices rather than
> asking you to document them, then lets you rename/annotate what it found. So you get an
> inventory without the data-entry. Doesn't do IPAM, doesn't do racks, doesn't try to.
> https://github.com/fxerkan/my_network_scanner

### D. "HA's device_tracker / ping integration is unreliable"

> Ping-based tracking fights Wi-Fi power saving — phones stop answering ICMP while asleep, so they
> flap.
>
> Author disclaimer: MyNeS (self-hosted, MIT) takes a different angle — ARP-level presence plus
> mDNS/SSDP, and it pushes everything into HA over MQTT Discovery. It also pulls HA's own device
> registry back and diffs it, which is how I found three Zigbee devices HA still listed that had
> been unplugged for months. https://github.com/fxerkan/my_network_scanner

### E. "How do I get alerted when a new device joins my Wi-Fi?"

> Some routers can do this natively — check yours first, it's the zero-effort option.
>
> If it can't: disclaimer, I maintain MyNeS. It scans on a schedule, diffs against the last scan,
> and fires on new / missing / changed devices. Notifications go out by Web Push (it runs its own,
> no third-party relay), webhook, e-mail, or straight into Home Assistant.
> https://github.com/fxerkan/my_network_scanner

### F. "Just installed CasaOS/Umbrel/Unraid — what should I run?"

Only reply here if the thread is genuinely asking for suggestions.

> For a first-week install: something that tells you what your network actually contains. Disclosure,
> mine is one option — MyNeS, a LAN scanner/inventory with a web UI. There's a
> [store/template] for it so it's a one-click install. Fair warning, it needs host networking to
> do ARP and mDNS properly. https://github.com/fxerkan/my_network_scanner

### G. Someone posts *"I found MyNeS and it's cool"* (it will happen)

Reply as a human, not a brand. Thank them, answer their question, and ask what they'd want next.
Do **not** paste the pitch under someone else's recommendation.

---

## 4. Launch posts

### r/selfhosted — the main one

**Title:** `MyNeS — a self-hosted network scanner that also finds your Zigbee, Z-Wave and BLE devices (MIT, Docker)`

> I've been building this for my own home lab and it's finally at the point where it's useful to
> other people, so: MyNeS (My Network Scanner).
>
> **The problem it started from.** I ran an IP scan on my LAN and it found 29 devices. I knew there
> were more like 60. Everything on Zigbee and Z-Wave is invisible to an IP scan — no IP, nothing to
> ping. So the inventory was never real.
>
> **What it does.** It discovers devices over ARP, mDNS/Bonjour, SSDP/UPnP, Matter, Bluetooth LE
> *and* by reading retained MQTT topics from Zigbee2MQTT / Z-Wave JS / Tasmota. That last one is the
> trick: it's the only way to see a radio device that has no IP. Everything lands in one inventory.
>
> On top of that:
> - Vendor lookup over a 1000+ entry OUI database, plus automatic device-type classification
> - Topology and force-directed graph views
> - Scan history — when a device first appeared, when it went quiet
> - Rule-based alerts on new / missing / changed devices, delivered by Web Push (its own, no
>   third-party relay), webhook, e-mail, or Home Assistant
> - Two-way Home Assistant integration: MQTT Discovery pushes devices in as entities, and the
>   REST/WebSocket side diffs what HA *thinks* it has against what's actually on the wire
> - Turkish and English UI, light/dark, installs as a PWA
>
> **The honest caveats.** It wants `network_mode: host` plus `NET_ADMIN`/`NET_RAW` — raw ARP and
> multicast simply don't work from a bridge network. It doesn't run as root and isn't `privileged`.
> Without those capabilities it degrades to a ping sweep and finds fewer devices rather than
> failing. Bluetooth LE needs a working adapter. And it's a scanner: only point it at your own
> network.
>
> No cloud, no account, no telemetry. MIT. Multi-arch image, so it's fine on a Pi.
>
> GitHub: https://github.com/fxerkan/my_network_scanner
> Docker: https://hub.docker.com/r/fxerkan/my_network_scanner
>
> Genuinely after feedback on what's missing — especially from anyone with a Z-Wave-heavy setup,
> since that's the corner I have least hardware to test against.

*(Attach 3–4 screenshots: home view, graph view, discovery, monitoring alerts.)*

### r/homelab

Same body, but lead harder on the inventory/topology angle and lighter on smart home:

**Title:** `Built a LAN scanner that keeps a real device inventory — ARP + mDNS + SSDP + BLE + MQTT, self-hosted (MIT)`

### r/homeassistant

**Title:** `MyNeS: scans your LAN and diffs it against Home Assistant's device registry — found 3 devices HA still listed that were unplugged`

Lead with the diff story; that is the hook for this audience. Mention MQTT Discovery early.

### r/HomeNetworking

Lead with "what is this device on my network", no self-hosting jargon, no Docker in the title.

### Show HN

**Title:** `Show HN: MyNeS – LAN scanner that also inventories Zigbee, Z-Wave and BLE devices`

HN wants the technical *why*. Open with the 29-vs-60 device problem, explain that MQTT retained
topics are the only channel that reveals a radio device with no IP, and be upfront about the
privilege requirements — HN will find them anyway and will respect you for saying it first.

### r/turkishlearning… no — Turkish channels

For [Donanım Haber forumları](https://forum.donanimhaber.com/) and Turkish self-hosting groups,
the same post in Turkish. Short version:

> **MyNeS — ev ağınızdaki her cihazı gösteren, kendi sunucunuzda çalışan ağ tarayıcı**
>
> IP taraması ağımda 29 cihaz buldu, oysa 60 civarı vardı. Zigbee ve Z-Wave cihazlarının IP'si yok,
> dolayısıyla IP taramasına görünmüyorlar. MyNeS bu yüzden ARP'ın yanında mDNS/Bonjour, SSDP/UPnP,
> Matter, Bluetooth LE ve MQTT de konuşuyor — Zigbee2MQTT ve Z-Wave JS'in retained topic'lerini
> okuyarak IP'si olmayan telsiz cihazları da envantere alıyor.
>
> Üretici tespiti (1000+ kayıtlık OUI veritabanı), otomatik cihaz tipi sınıflandırma, topoloji ve
> graf görünümleri, tarama geçmişi, yeni/kaybolan/değişen cihaz uyarıları (Web Push, webhook,
> e-posta, Home Assistant) ve çift yönlü Home Assistant entegrasyonu var.
>
> Bulut yok, hesap yok, telemetri yok. MIT lisanslı, Türkçe ve İngilizce arayüz, Docker imajı Pi'de
> de çalışıyor. Sadece kendi ağınızı tarayın.
>
> https://github.com/fxerkan/my_network_scanner

---

## 5. The one-liners (keep these consistent everywhere)

- **Tagline (EN):** See every device on your home network — including the ones an IP scan cannot find.
- **Tagline (TR):** Ev ağınızdaki her cihazı görün — IP taramasının bulamadıklarını da.
- **One sentence:** MyNeS is a self-hosted LAN scanner that inventories your network over ARP, mDNS, SSDP, Matter, Bluetooth LE and MQTT, alerts you when it changes, and syncs two ways with Home Assistant.
- **The hook, always:** *"An IP scan found 29 of my 60 devices. Zigbee and Z-Wave have no IP."*
- **GitHub topics to set:** `network-scanner` `homelab` `self-hosted` `home-assistant` `mdns` `ssdp` `matter` `zigbee` `zwave` `bluetooth-le` `mqtt` `network-monitoring` `flask` `docker` `raspberry-pi`

---

## 6. Sequencing

Do **not** fire everything at once — a launch that lands on three subreddits in one hour reads as
a campaign, and one removal cascades.

| Week | Action |
|------|--------|
| 0 | Finish [`PUBLISHING.md` §0](PUBLISHING.md) prerequisites. Set GitHub topics. Add to AlternativeTo. |
| 1 | r/selfhosted weekly thread (low stakes, tests the pitch). Start the weekly search sweep in §2. |
| 2 | r/selfhosted main launch post. Answer every comment within the first 4 hours — that window decides the thread. |
| 3 | r/homelab, then r/homeassistant a few days later. |
| 4 | Show HN, on a Tuesday–Thursday morning US time. |
| 5+ | Reply-to-threads only (§3), plus store submissions landing one by one. Each store acceptance is a legitimate small post of its own: *"MyNeS is now a one-click install on Unraid."* |
