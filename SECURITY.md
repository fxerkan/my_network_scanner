# Security Policy

## Supported versions

MyNeS is developed on `main`. Only the latest released version receives fixes.

| Version | Supported |
| --- | --- |
| 1.3.x | ✅ |
| < 1.3 | ❌ — upgrade |

## Reporting a vulnerability

Please **do not** open a public issue for a security problem.

- Use [GitHub Security Advisories](https://github.com/fxerkan/my_network_scanner/security/advisories/new), or
- e-mail **fxerkan@gmail.com** with `MyNeS security` in the subject.

Include what you can: affected version, how to reproduce, and what an attacker gains. A working
proof of concept helps but is not required.

This is a spare-time project, not a funded one. Expect an acknowledgement within a week and a fix
timeline in the reply. There is no bug bounty.

## Scope

In scope:

- The Flask web application and its API (`mynes/web/`)
- Credential storage and encryption (`mynes/security/`)
- Export sanitisation (`mynes/security/sanitizer.py`)
- The privilege helpers (`mynes/platform/privileges.py`, `mynes/platform/service.py`)
- The published Docker image

Out of scope:

- Vulnerabilities in devices MyNeS scans. MyNeS reports what it finds; it does not exploit.
- Findings that require an attacker already on your LAN *and* already authenticated to MyNeS,
  unless they cross a privilege boundary.
- Anything needing physical access to the host.

## Design decisions you should know about

These are deliberate, documented, and not vulnerabilities in themselves — but they define the
threat model, so read them before deploying.

**MyNeS runs on the host network with `NET_ADMIN` and `NET_RAW`.** Raw ARP frames and mDNS/SSDP
multicast cannot cross a bridge network. It does **not** run as root (`USER scanner`, uid 1000)
and it is **not** `privileged`. Without these capabilities it degrades to a ping sweep rather
than failing.

**A web request can never escalate privileges.** `mynes/platform/privileges.py` prints the
narrow, per-OS command needed (Linux `setcap`, macOS ChmodBPF, Windows Npcap) and only executes
it under an explicit `--apply` flag from a terminal, so the OS password prompt appears in the
user's own shell.

**There is no authentication by default.** MyNeS assumes a trusted LAN. Do not expose it to the
internet without putting an authenticating reverse proxy in front of it. Its inventory is a map
of your home — treat it as sensitive.

**Credentials at rest** are encrypted with Fernet over PBKDF2-HMAC-SHA256 (100,000 iterations).
The master key comes from `MYNES_PASSWORD` or `config/.master_password` (gitignored, mode 600,
auto-generated if absent). `config/config.json` is tracked in git and must never contain
secrets — `tests/test_smoke.py` asserts this.

**Exports are sanitised** by `mynes/security/sanitizer.py`, which strips credentials and other
sensitive fields. If you find a field that leaks through, that *is* a reportable bug.

## Using MyNeS responsibly

MyNeS is a network scanner. Scanning a network you do not own or have permission to test is
illegal in many jurisdictions. Only scan networks you own.
