# Plan: per-device DNS and telemetry visibility for MyNeS (AdGuard Home on rpifx)

Status: **planned**. First work session: weekend of 2026-11-28.
Owner: Erkan. Context: PR #13 (`fix/scan-persistence-net-tools`).

## Why

MyNeS runs on rpifx, which hangs off a switch. On a switched LAN a host only
sees broadcast/multicast traffic and the traffic addressed to it. It never sees
another device's unicast flows. The passive "Network Insights" view therefore
shows four things only:
- what devices announce themselves (DHCP, mDNS, SSDP, Tuya broadcasts);
- the internet path seen from rpifx;
- the DNS servers handed out by DHCP;
- each vendor's *expected* cloud endpoints.

It cannot show which domains each device actually resolves.

To see per-device DNS, the device's DNS queries have to reach something MyNeS
can read **with the client IP intact**.

Today the Zyxel EX3501 forwards every LAN query to **AdGuard DNS (SaaS,
adguard-dns.io)**. AdGuard DNS sees one client: the router's public IP. So its
query log cannot be broken down per device either.

ARP spoofing / MITM is **out of scope on purpose**: it is fragile and can take
the LAN down.

## Target architecture

```
LAN devices --DHCP option 6--> rpifx:53 (AdGuard Home, CasaOS app)
                                  |  upstream: AdGuard DNS (DoH, personal endpoint
                                  |            https://d.adguard-dns.com/dns-query/<id>)
                                  |  fallback: 1.1.1.1 / 9.9.9.9
                                  v
                MyNeS  <-- AdGuard Home API /control/querylog, /control/stats
```

- AdGuard Home keeps the **client IP/MAC** of every query. MyNeS already maps
  IP to device, so each query lands on a named device.
- The existing AdGuard DNS (SaaS) account stays as the upstream, so its
  filtering lists and statistics keep working. Only the edge resolver moves to
  rpifx.

## Steps

1. **Install AdGuard Home as a CasaOS app.** Follow the CasaOS app rule: the
   compose lives in `/var/lib/casaos/apps/adguardhome/` with an `x-casaos`
   block.
   - Use host network, port 53/udp+tcp, web UI on 3000 → then 80xx.
   - Check that nothing else binds :53. `systemd-resolved` is not used on
     rpifx; Tailscale MagicDNS uses 100.100.100.100, not :53.
   - Store the admin credentials in concealer (`adguard-home-admin`).
2. **Point AdGuard Home's upstream at the personal AdGuard DNS DoH endpoint.**
   Add the fallback upstreams. Turn on client-IP logging, 90-day retention.
3. **Name the clients.** Optionally let MyNeS push its device names into
   AdGuard Home's persistent clients via `/control/clients/add`.
4. **Change Zyxel DHCP to hand out DNS = 192.168.1.62.**
   - Secondary DNS: `94.140.14.14` (AdGuard DNS anycast), so DNS survives if
     rpifx is down. Trade-off: some queries then bypass the log.
   - This is the only router change, and it is reversible.
5. **Add an AdGuard Home source to MyNeS.** The pluggable `dns_sources`
   interface from the passive Insights work gets an `adguard_home` adapter.
   - Base URL and credentials come from Settings › Integrations, stored in
     `data/`, never in config.json.
   - Poll `/control/querylog?older_than=` incrementally.
   - Aggregate per client into domain counts, first/last seen and blocked
     counts.
   - Classify domains as vendor cloud, telemetry/analytics, ads, CDN or other,
     using a curated table plus the AdGuard Home filter reason.
6. **UI.** In Insights › Devices, show for each device:
   - top domains;
   - telemetry share;
   - new or never-seen domains (an alert rule);
   - countries/ASNs of the resolved IPs (offline GeoLite DB, optional).
7. **Grafana.** Add a `mynes_dns` measurement: queries per device/category.
8. **Alerts.** Raise an alert for:
   - a device talking to a domain category it never used before;
   - a device that suddenly does a lot of DNS;
   - DNS answering from a resolver other than rpifx (DNS bypass, e.g.
     hard-coded 8.8.8.8 — visible later only with router help).

## Alternatives considered

- **AdGuard DNS (SaaS) API only.** Its query log shows domains but not *which
  LAN device* asked, because the Zyxel NATs every query. It is still useful as
  a whole-house domain list. MyNeS can read it with an API key as a fallback
  source.
- **Pi-hole.** Equivalent; AdGuard Home was picked to match the existing
  AdGuard account and lists.
- **Router NetFlow/conntrack.** The EX3501 exposes neither.

## Done when

- Every LAN device shows the domains it resolved in MyNeS Insights.
- DNS keeps working with rpifx powered off (secondary resolver).
- Grafana shows DNS volume per device and category.
