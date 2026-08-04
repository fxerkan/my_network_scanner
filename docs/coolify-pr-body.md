## Changes

- Added My Network Scanner (MyNeS) application template, it is a simple user friendly LAN devices scanner
- See every device on your home network - including the Zigbee, Z-Wave, Matter and Bluetooth LE ones an IP scan cannot find.
  
- Host networking is required: raw ARP frames and mDNS/SSDP multicast do not cross a bridge etwork, so the proxy cannot route by container name and the UI is served on host port 5883.

## Issues

- N/A — new one-click service.

## Category

- [ ] Bug fix
- [ ] Improvement
- [ ] New feature
- [x] Adding new one click service
- [ ] Fixing or updating existing one click service

## Preview

![MyNeS device inventory](https://raw.githubusercontent.com/fxerkan/my_network_scanner/main/assets/mynes.png)

## AI Assistance

- [ ] AI was NOT used to create this PR
- [x] AI was used (please describe below)

**If AI was used:**

- Tools used: Claude Code
- How extensively: it drafted the compose template and this PR scaffold from the project's
  existing deploy files. I wrote the Changes section, reviewed every line of the template, and
  tested the deployment myself before opening this.

## Testing

Deployed the template on a local Coolify instance, confirmed the container starts, the health
check on `/api/version` passes, and the UI is reachable on host port 5883 via from my raspberry pi with devices appearing in the first scan.

## Contributor Agreement

> [!IMPORTANT]
>
> - [x] I have read and understood the [contributor guidelines](https://github.com/coollabsio/coolify/blob/v4.x/CONTRIBUTING.md). If I have failed to follow any guideline, I understand that this PR may be closed without review.
> - [x] I have searched [existing issues](https://github.com/coollabsio/coolify/issues) and [pull requests](https://github.com/coollabsio/coolify/pulls) (including closed ones) to ensure this isn't a duplicate.
> - [x] I have tested all the changes thoroughly with a local development instance of Coolify and I am confident that they will work as expected when a maintainer tests them.
