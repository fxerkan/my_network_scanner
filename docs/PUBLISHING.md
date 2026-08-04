# Publishing MyNeS to home-lab app stores

Every manifest lives under [`deploy/marketplaces/`](../deploy/marketplaces/). This document is
the checklist for getting each one accepted.

Do the **prerequisites** first. Half of these stores reject a submission that pins a `latest`
tag or 404s on an icon URL.

---

## Status — v1.3.0 submission round

| Store | State | Link |
|-------|-------|------|
| GitHub release | ✅ live | [v1.3.0](https://github.com/fxerkan/my_network_scanner/releases/tag/v1.3.0) |
| Docker Hub | ✅ live, description auto-synced | [`fxerkan/my_network_scanner`](https://hub.docker.com/r/fxerkan/my_network_scanner) `1.3.0` / `1.3` / `latest`, amd64 + arm64 |
| CasaOS third-party store | ✅ **live now, no review needed** | [`fxerkan/mynes-casaos-store`](https://github.com/fxerkan/mynes-casaos-store) |
| Home Assistant add-on | ✅ **live now, no review needed** | [`fxerkan/mynes-addon`](https://github.com/fxerkan/mynes-addon) |
| CasaOS official store | ⏳ PR open | [CasaOS-AppStore#993](https://github.com/IceWhaleTech/CasaOS-AppStore/pull/993) |
| Umbrel | ⏳ PR open | [umbrel-apps#5955](https://github.com/getumbrel/umbrel-apps/pull/5955) |
| Runtipi | ⏳ PR open | [runtipi-appstore#11796](https://github.com/runtipi/runtipi-appstore/pull/11796) |
| Cosmos | ⏳ PR open | [cosmos-servapps-official#264](https://github.com/azukaar/cosmos-servapps-official/pull/264) |
| Coolify | 🔵 branch ready, **you open the PR** | see [`coolify-pr-body.md`](coolify-pr-body.md) |
| Unraid CA | ⏳ issue open | [AppFeed#39](https://github.com/Squidly271/AppFeed/issues/39) |
| Portainer (Qballjos collection) | ⏳ PR open | [portainer_templates#74](https://github.com/Qballjos/portainer_templates/pull/74) |
| Portainer (Lissy93 aggregator) | ❌ closed — correctly | [#127](https://github.com/Lissy93/portainer-templates/pull/127): `sources.csv` tracks upstream *collections*, not single templates. Qballjos is already a tracked source, so merging #74 gets MyNeS here transitively. |
| awesome-selfhosted | ⏳ PR open | [awesome-selfhosted-data#2840](https://github.com/awesome-selfhosted/awesome-selfhosted-data/pull/2840) |
| awesome-homelab | ⏳ PR open | [awesome-homelab#112](https://github.com/AwesomeHomelab/awesome-homelab/pull/112) |
| awesome-casaos | ⏳ PR open | [Awesome-CasaOS#14](https://github.com/IceWhaleTech/Awesome-CasaOS/pull/14) |

**Install URLs to hand out today:**

```
CasaOS  → App Store → Add Source:
  https://cdn.jsdelivr.net/gh/fxerkan/mynes-casaos-store@gh-pages/store/main.zip

Home Assistant → Add-ons → ⋮ → Repositories:
  https://github.com/fxerkan/mynes-addon

Portainer → Settings → App Templates:
  https://raw.githubusercontent.com/fxerkan/my_network_scanner/main/deploy/marketplaces/portainer/portainer-template.json
```

### What review taught us

Worth reading before the next store, because none of it is in any documentation:

- **Coolify** auto-closes on mechanical rules in `.github/workflows/pr-quality.yaml`: base branch
  must be `next` (not `v4.x`, not `main`), the PR template is mandatory with a strict
  *Contributor Agreement* section, description ≤ 2500 chars, ≤ 5 inline code refs, and **≤ 10
  added comment lines** — the first template had 11. Their template also tells AI agents to put a
  specific word at the top of the description; that word is in the workflow's `blocked-terms`, so
  writing it auto-rejects the PR. Disclose AI use in the *AI Assistance* section instead.
- **Umbrel** CI requires `releaseNotes: ""` and `gallery: []` for a *new* app (they are for
  updates), the `${APP_DATA_DIR}` bind-mount directories committed as real folders, and icon and
  gallery images posted in the PR body rather than committed. Host networking and `NET_ADMIN` /
  `NET_RAW` are warnings, not errors — they just want them justified.
- **Lissy93's portainer-templates** is an aggregator of collections. Submit to a collection it
  already tracks; do not add yourself as a source.
- **CasaOS** rejects an app without a reverse-domain `x-casaos.id`, and silently builds an empty
  `version` without `x-casaos.version`, which stops CasaOS distinguishing an update from a
  reinstall.

**Still to do by hand** (needs a browser login this tooling cannot do):

- **AlternativeTo** — add MyNeS to the [Fing](https://alternativeto.net/software/fing/),
  [Nmap](https://alternativeto.net/software/nmap/) and
  [Fingbox](https://alternativeto.net/software/fingbox) alternatives pages. Free, permanent,
  and it ranks in search. Highest value per minute of anything left on this list.
- **Unraid forum support thread** — AppFeed#39 offers to repoint `<Support>` at one. Create it at
  [forums.unraid.net](https://forums.unraid.net/) if they ask.
- **awesome-home-assistant** and **awesome-docker** PRs — see §10.
- The community outreach in [`OUTREACH.md`](OUTREACH.md).

---

## 0. Prerequisites (do these once, before any submission)

| # | What | Status |
|---|------|--------|
| 1 | Tag and release `v1.3.0` on GitHub | ✅ `.github/workflows/docker-publish.yml` builds `linux/amd64,linux/arm64` on `v*` tags. |
| 2 | Confirm `fxerkan/my_network_scanner:1.3.0` is a multi-arch manifest | ✅ verify any time with `docker manifest inspect fxerkan/my_network_scanner:1.3.0` — must list amd64 **and** arm64. |
| 3 | Rewrite the Docker Hub description | ✅ `docs/DOCKER_README.md` rewritten (the old one still documented `LAN_SCANNER_PASSWORD` and `privileged: true` and never mentioned host networking). A `peter-evans/dockerhub-description` step in the publish workflow now pushes it on every `main` build, so it cannot rot again. |
| 4 | `256×256` PNG icon at `assets/icon.png` | ✅ generated by `scripts/make_store_assets.py`, which redraws `assets/logo.svg` with PIL — no SVG dependency. Also emits `assets/icon-128.png` for the HA add-on. Note `assets/mynes.png` is a *screenshot*, not the logo; do not use it as an icon. |
| 5 | `assets/store/1.jpg`, `2.jpg`, `3.jpg` (1920×1080) | ✅ same script. Screenshots are letterboxed on brand blue rather than cropped, so nothing is cut off. |
| 6 | `SECURITY.md` + `LICENSE` at repo root | ✅ both present. `SECURITY.md` documents the threat model, which is what Umbrel and awesome-selfhosted reviewers actually read. |
| 7 | "Why host networking, why NET_RAW" note in the README | ✅ in `README.md`, `docs/README_ENG.md` and `docs/DOCKER_README.md`. |

Regenerate the store assets after changing the logo or a screenshot:

```bash
.venv/bin/python scripts/make_store_assets.py --demo   # self-check
.venv/bin/python scripts/make_store_assets.py
```

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
