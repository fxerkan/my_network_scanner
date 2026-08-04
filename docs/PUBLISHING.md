# Publishing MyNeS to home-lab app stores

Every manifest lives under [`deploy/marketplaces/`](../deploy/marketplaces/). This document is
the checklist for getting each one accepted.

Do the **prerequisites** first. Half of these stores reject a submission that pins a `latest`
tag or 404s on an icon URL.

---

## 0. Prerequisites (do these once, before any submission)

| # | What | Why |
|---|------|-----|
| 1 | Tag and release `v1.3.0` on GitHub | Several stores require an immutable version tag, not `latest`. `.github/workflows/docker-publish.yml` already builds `linux/amd64,linux/arm64` on `v*` tags. |
| 2 | Confirm `fxerkan/my_network_scanner:1.3.0` exists on Docker Hub and is a multi-arch manifest | `docker manifest inspect fxerkan/my_network_scanner:1.3.0` should list amd64 **and** arm64. Raspberry Pi / Orange Pi users are the target audience. |
| 3 | Rewrite the Docker Hub description | `docs/DOCKER_README.md` is stale: it still documents `LAN_SCANNER_PASSWORD` and `privileged: true`, and never mentions host networking. Replace it with the current `deploy/docker-compose.yml` story before store reviewers read it. |
| 4 | Add a `256×256` PNG icon at `assets/icon.png` | `assets/logo.svg` is 534 bytes and several stores (Unraid, Portainer, Cosmos) want raster. `assets/mynes.png` is 624 KB — too heavy for a store icon. |
| 5 | Add `assets/store/1.jpg`, `2.jpg`, `3.jpg` (1920×1080) | Umbrel's gallery expects exactly this. Crop from `assets/screenshots/`. |
| 6 | Add a `SECURITY.md` and confirm `LICENSE` is at repo root | awesome-selfhosted and Umbrel review both check. |
| 7 | Write a one-paragraph "why host networking, why NET_RAW" note in the README | Every reviewer will ask. Getting ahead of it shortens review by days. |

**The recurring review question.** MyNeS asks for `network_mode: host` + `NET_ADMIN` + `NET_RAW`.
Have this answer ready, verbatim, in every PR description:

> MyNeS sends raw ARP frames and listens for mDNS/SSDP multicast. Both require the host network
> namespace — from a bridge network it can only see the bridge, not the LAN. `NET_RAW` lets it
> build ARP frames; `NET_ADMIN` lets it read interface state. It does **not** run as root
> (`USER scanner`, uid 1000) and it is **not** `privileged`. Without these capabilities it
> degrades to a ping sweep plus the OS ARP cache rather than failing.

---

## 1. Docker Hub — *already live, needs a refresh*

- Image: <https://hub.docker.com/r/fxerkan/my_network_scanner>
- Publishing is automated by `.github/workflows/docker-publish.yml`.

**To do:** paste the rewritten `docs/DOCKER_README.md` into the Docker Hub repository
description, add the topics `network`, `homelab`, `home-assistant`, `monitoring`, `iot`, and
link the GitHub repo. Also mirror to GHCR (`ghcr.io/fxerkan/my_network_scanner`) — some stores
prefer it, and it costs one extra `docker/login-action` step.

---

## 2. CasaOS / ZimaOS App Store

**Manifest:** `deploy/marketplaces/casaos/docker-compose.yml`

CasaOS has two routes, and you should do **both** — the third-party store first, because it is
live the moment you push, and the official store second, because that is where the users are.

### 2a. Your own third-party store (fast, no review)

The store format is a repo containing `store-config.json` at the root and `Apps/<AppName>/`
folders, built into a `dist/` tree by `scripts/build_dist.sh`, published by GitHub Pages or any
static host. Users paste the resulting URL into CasaOS → App Store → **Add Source**.

1. Fork <https://github.com/IceWhaleTech/CasaOS-AppStore> as a template, or create
   `github.com/fxerkan/mynes-casaos-store`.
2. Root `store-config.json`:
   ```json
   {
     "name": "MyNeS Store",
     "description": "MyNeS - My Network Scanner",
     "author": "fxerkan",
     "url": "https://fxerkan.github.io/mynes-casaos-store"
   }
   ```
3. `Apps/MyNeS/docker-compose.yml` ← copy from `deploy/marketplaces/casaos/`.
4. `Apps/MyNeS/icon.svg`, `thumbnail.png`, `screenshot-1..3.png`.
5. Run `./scripts/build_dist.sh` with `BASE_URL` set to your Pages URL. It emits
   `dist/index.json`, `dist/store.json`, `dist/apps/<app-id>/` and `dist/store/main.zip`.
6. Publish `dist/` to GitHub Pages. The URL users add is the built store URL, e.g.
   `https://fxerkan.github.io/mynes-casaos-store/store/main.zip`.
7. **Then list it** at <https://awesome.casaos.io/content/3rd-party-app-stores/list.html> by
   opening a PR against <https://github.com/IceWhaleTech/awesome-casaos>.

### 2b. Official CasaOS/ZimaOS App Store (reviewed)

Open an issue on <https://github.com/IceWhaleTech/CasaOS-AppStore> asking to contribute, then a
PR adding `Apps/MyNeS/`. Their `validator.yml` workflow checks the compose file, so run it
locally first. Note their convention: bind mounts go to `/DATA/AppData/$AppID/...` and the
compose top-level `name:` must equal the app id — both already done in our manifest.

---

## 3. Umbrel App Store

**Manifests:** `deploy/marketplaces/umbrel/umbrel-app.yml` + `docker-compose.yml`

1. Fork <https://github.com/getumbrel/umbrel-apps>.
2. Create `mynes/` with the two manifests plus `mynes/1.jpg`, `2.jpg`, `3.jpg` (gallery) and
   `mynes/icon.svg`.
3. **Pin the image by digest.** Umbrel requires `image: fxerkan/my_network_scanner:1.3.0@sha256:…`.
   Get it with `docker buildx imagetools inspect fxerkan/my_network_scanner:1.3.0`.
4. Open the PR, then edit `umbrel-app.yml`'s `submission:` field to point at that PR's own URL —
   this is a required, slightly circular step they enforce.

**Expect pushback on host networking.** It is allowed (their own Home Assistant app uses
`network_mode: host` and skips `app_proxy` entirely — our manifest follows that exact pattern),
but be ready with the prerequisites answer above. Umbrel review is the slowest of the lot; budget
weeks, not days.

---

## 4. Runtipi App Store

**Manifests:** `deploy/marketplaces/runtipi/config.json` + `docker-compose.yml`

1. Fork <https://github.com/runtipi/runtipi-appstore>.
2. Create `apps/mynes/` containing `config.json`, `docker-compose.yml`,
   `metadata/description.md` (reuse the English README intro) and `metadata/logo.jpg`.
3. Note `"dynamic_config": false` in our `config.json` — Runtipi's dynamic compose format cannot
   express `network_mode: host`, so the raw compose file is used as-is. Say this in the PR.
4. Runtipi bumps `tipi_version` on every change; increment it, not just `version`, on updates.

---

## 5. Cosmos Cloud (Servapps)

**Manifests:** `deploy/marketplaces/cosmos/cosmos-compose.json` + `description.json`

1. Fork <https://github.com/azukaar/cosmos-servapps-official>.
2. Create `servapps/MyNeS/` with both JSON files plus `icon.png` and `screenshots/`.
3. `"cosmos-force-network-secured": "false"` is deliberate — Cosmos's secured network is a bridge,
   which would blind the scanner. Explain that in the PR body.

---

## 6. Unraid Community Applications

**Manifest:** `deploy/marketplaces/unraid/mynes.xml`

Unraid CA does not host templates; it indexes them from your own repo.

1. Keep `mynes.xml` where it is — `<TemplateURL>` already points at the raw GitHub URL in this
   repo, which is what CA follows for updates.
2. Add the repo to CA by posting in the
   [Community Applications support thread](https://forums.unraid.net/topic/38582-plug-in-community-applications/),
   or open a PR/issue at <https://github.com/Squidly271/AppFeed>.
3. Create an Unraid forum support topic first — `<Support>` should ideally point at a forum
   thread; a GitHub Issues link is accepted but flagged.
4. Unraid users are the single best-fit audience for this app. Prioritise this one.

---

## 7. Portainer App Templates

**Manifest:** `deploy/marketplaces/portainer/portainer-template.json`

Portainer has no central submission. Two routes:

- **Self-serve:** users point Portainer → Settings → App Templates at the raw URL of our file:
  `https://raw.githubusercontent.com/fxerkan/my_network_scanner/main/deploy/marketplaces/portainer/portainer-template.json`
  Document that URL in the README.
- **Community lists:** open a PR against the widely-used aggregators, e.g.
  <https://github.com/Lissy93/portainer-templates> and
  <https://github.com/mycroftwilde/portainer_templates>. These carry real traffic.

---

## 8. Coolify

**Manifest:** `deploy/marketplaces/coolify/mynes.yaml`

1. Fork <https://github.com/coollabsio/coolify>.
2. Drop the file at `templates/compose/mynes.yaml` and the logo at
   `public/svgs/mynes.svg`.
3. The `# documentation:` / `# slogan:` / `# tags:` / `# logo:` / `# port:` header comments are
   the metadata format — they are parsed, not decorative.

---

## 9. Home Assistant add-on

**Manifests:** `deploy/marketplaces/homeassistant-addon/`

This one needs its own repository because Supervisor scans an add-on repo's **root** for folders
containing `config.yaml`.

1. Create `github.com/fxerkan/mynes-addon`.
2. Copy `repository.yaml` to its root and the whole `mynes/` folder next to it. Add
   `mynes/icon.png` (128×128) and `mynes/logo.png`.
3. The add-on reuses the published Docker Hub image, so there is nothing to build. `version:` in
   `config.yaml` must exactly match a real image tag.
4. Users add it via Settings → Add-ons → Add-on Store → ⋮ → Repositories.
5. Once it has users, submit to <https://github.com/hassio-addons/repository> community list and
   the HACS-adjacent add-on listings.

Given MyNeS already speaks MQTT Discovery and the HA REST/WebSocket API, this is the highest
strategic-value store on the list even though it has the smallest install button.

---

## 10. Awesome-list PRs (free distribution, do these all in one afternoon)

### awesome-selfhosted

PR against <https://github.com/awesome-selfhosted/awesome-selfhosted-data>, file
`software/mynes.yml`:

```yaml
name: MyNeS
website_url: https://github.com/fxerkan/my_network_scanner
description: Discover, identify and monitor every device on your LAN - including the Zigbee, Z-Wave, Matter and Bluetooth LE devices an IP scan cannot see - with Home Assistant integration.
licenses:
  - MIT
platforms:
  - Python
  - Docker
tags:
  - Monitoring
source_code_url: https://github.com/fxerkan/my_network_scanner
```

Their bot fills in `stargazers_count` and `updated_at`. Read their `CONTRIBUTING.md` first —
they reject projects without a public demo *or* screenshots, and without at least a few months
of commit history.

### awesome-homelab

PR against <https://github.com/AwesomeHomelab/awesome-homelab> (default branch `master`), file
`data/networking.yaml`. Follow the existing entry shape in that file; keep the description to one
line. Their `AGENTS.md` and `.github/CONTRIBUTING.md` describe the validation script — run
`pnpm install && pnpm run <validate script>` before opening the PR.

### The rest, in descending order of traffic

| List | Where |
|------|-------|
| awesome-casaos (3rd-party stores) | <https://github.com/IceWhaleTech/awesome-casaos> |
| awesome-home-assistant | <https://github.com/frenck/awesome-home-assistant> |
| awesome-docker | <https://github.com/veggiemonk/awesome-docker> |
| awesome-selfhosted-zh (TR/zh audiences) | search "awesome selfhosted" forks |
| Awesome Raspberry Pi | <https://github.com/thibmaek/awesome-raspberry-pi> |
| selfh.st (weekly newsletter — submit via their site) | <https://selfh.st/> |

---

## 11. Deliberately skipped, and when to revisit

| Store | Why skipped | Revisit when |
|-------|-------------|--------------|
| **TrueNAS SCALE apps** | The community catalog (`truenas/apps`) demands a full app spec plus their own CI; host networking on SCALE is additionally awkward. | After 500+ Docker Hub pulls, so the effort is justified. |
| **YunoHost** | Packaging is a bespoke bash framework, not Docker. Weeks of work. | Only if a YunoHost user asks. |
| **DietPi software catalog** | Requires an install script maintained inside DietPi's own repo. | Same. |
| **Synology / QNAP** | Both need vendor-signed packages and host networking is restricted. | Probably never. |
| **Dockge / Komodo / Dokploy** | These consume plain compose files; `deploy/docker-compose.yml` already works. Nothing to submit. | N/A — just document it. |

---

## Suggested order

1. Prerequisites (§0) — one afternoon.
2. Unraid CA + Portainer community lists — best audience fit, lowest friction.
3. CasaOS third-party store — live immediately, no review.
4. Awesome-list PRs (§10) — free, permanent.
5. Runtipi + Cosmos + Coolify — small, friendly maintainer teams.
6. Home Assistant add-on repo.
7. CasaOS official store, then Umbrel — slowest reviews, start them last but expect them to
   finish last too.
