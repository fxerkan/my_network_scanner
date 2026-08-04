# Marketplace manifests

One folder per app store. Submission steps for each live in [`docs/PUBLISHING.md`](../../docs/PUBLISHING.md);
community outreach copy lives in [`docs/OUTREACH.md`](../../docs/OUTREACH.md).

| Folder | Store | Where the file goes |
|--------|-------|---------------------|
| `casaos/` | CasaOS / ZimaOS | `Apps/MyNeS/docker-compose.yml` in a CasaOS store repo |
| `umbrel/` | Umbrel | `mynes/` in `getumbrel/umbrel-apps` |
| `runtipi/` | Runtipi | `apps/mynes/` in `runtipi/runtipi-appstore` |
| `cosmos/` | Cosmos Cloud | `servapps/MyNeS/` in `azukaar/cosmos-servapps-official` |
| `unraid/` | Unraid Community Applications | stays here — CA follows the `<TemplateURL>` |
| `portainer/` | Portainer App Templates | stays here — users add the raw URL |
| `coolify/` | Coolify | `templates/compose/mynes.yaml` in `coollabsio/coolify` |
| `homeassistant-addon/` | Home Assistant add-on | root of a dedicated add-on repo |

Dockge, Komodo and Dokploy need nothing here — they consume
[`deploy/docker-compose.yml`](../docker-compose.yml) directly.

**Three things every one of these gets wrong if you edit carelessly:**

1. `network_mode: host` is not optional. ARP frames and mDNS/SSDP multicast do not cross a bridge
   network. Drop it and the scanner sees the Docker bridge instead of the LAN.
2. `NET_ADMIN` + `NET_RAW`, but **not** `privileged`. The image runs as uid 1000. A web app that
   parses network input should not be root.
3. Bump the pinned image tag in every file when releasing. `grep -rn '1\.3\.0' deploy/marketplaces/`
   finds them all.
