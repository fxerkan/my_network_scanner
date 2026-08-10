"""Metrics export for Grafana - two backends, both optional.

**Prometheus (pull)**: `prometheus_text()` renders the current device/alert state
in the Prometheus text exposition format (v0.0.4). MyNeS exposes it at
`/api/metrics`; point a Prometheus scrape or Grafana Agent at that path and the
dashboards fill themselves. No dependency - it is a string builder.

**InfluxDB 2 (push)**: `influx_line_protocol()` renders the same state as InfluxDB
line protocol, and `push_influx()` POSTs it to an InfluxDB 2 `/api/v2/write`
endpoint over stdlib urllib. The monitoring scheduler calls this after every scan
when InfluxDB is configured, so a home lab already running Influx+Grafana gets a
time series with no extra moving parts.

Both halves are optional and degrade the DiscoveryBackend way: a missing/broken
Influx endpoint returns ``(False, reason)`` and never raises, so a scan is never
broken by a metrics push.

The Influx **token is a secret**: it is read from the environment or from
``data/monitoring.json`` only, never from ``config/config.json`` (which is tracked
in git).
"""

from __future__ import annotations

import logging
import os
import time
import urllib.error
import urllib.parse
import urllib.request

from mynes.paths import load_local

log = logging.getLogger(__name__)

SETTINGS_FILE = "monitoring.json"

SEVERITIES = ("critical", "high", "medium", "low", "info")

# Home Assistant's build_scanner logic uses the same online check; keep the two
# in step by mirroring it rather than importing (this module has no HA dep).
_ONLINE_STATES = ("online", "up", "active")


def _is_online(device: dict) -> bool:
    return str(device.get("status", "")).lower() in _ONLINE_STATES or bool(device.get("is_online"))


def _severity(alert: dict) -> str:
    """Map an alert's severity onto the five buckets we export.

    The monitoring rules only emit info/warning/critical, but the security
    findings carry high/medium/low - normalise both so every alert lands in a
    bucket and nothing is silently dropped.
    """
    sev = str(alert.get("severity", "info")).lower()
    if sev in SEVERITIES:
        return sev
    if sev == "warning":
        return "medium"
    if sev in ("error", "danger"):
        return "high"
    return "info"


def _response_ms(device: dict):
    """A numeric response time in ms, or None. Accepts the few shapes the scan
    produces: response_time (ms), response_ms, latency_ms."""
    for key in ("response_ms", "response_time", "latency_ms"):
        val = device.get(key)
        if val in (None, ""):
            continue
        try:
            return float(val)
        except (TypeError, ValueError):
            continue
    return None


# ---------------------------------------------------------------------------
# Prometheus text exposition format (pull)
# ---------------------------------------------------------------------------


def _esc_label(value) -> str:
    """Escape a Prometheus label value: backslash, double-quote, newline."""
    return str(value if value is not None else "").replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _labels(pairs) -> str:
    inner = ",".join(f'{k}="{_esc_label(v)}"' for k, v in pairs)
    return "{" + inner + "}" if inner else ""


def prometheus_text(devices: list, alerts: list) -> str:
    """Render the current state as Prometheus text exposition format (v0.0.4)."""
    devices = [d for d in (devices or []) if isinstance(d, dict)]
    alerts = [a for a in (alerts or []) if isinstance(a, dict)]

    online = sum(1 for d in devices if _is_online(d))
    total = len(devices)
    by_sev = {s: 0 for s in SEVERITIES}
    for a in alerts:
        by_sev[_severity(a)] += 1

    lines: list[str] = []

    def gauge(name, help_text, value, labels=""):
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} gauge")
        lines.append(f"{name}{labels} {value}")

    gauge("mynes_devices_total", "Total devices known to MyNeS.", total)
    gauge("mynes_devices_online", "Devices currently online.", online)
    gauge("mynes_devices_offline", "Devices currently offline.", total - online)
    gauge("mynes_alerts_total", "Total alerts in the alert store.", len(alerts))

    # Severity gauge: one HELP/TYPE, one line per bucket.
    lines.append("# HELP mynes_alerts_by_severity Alerts grouped by severity.")
    lines.append("# TYPE mynes_alerts_by_severity gauge")
    for sev in SEVERITIES:
        lines.append(f'mynes_alerts_by_severity{{severity="{sev}"}} {by_sev[sev]}')

    # Per-device up/down.
    lines.append("# HELP mynes_device_up Device reachability (1 = online, 0 = offline).")
    lines.append("# TYPE mynes_device_up gauge")
    for d in devices:
        labels = _labels(
            [
                ("ip", d.get("ip") or ""),
                ("mac", d.get("mac") or ""),
                ("name", d.get("alias") or d.get("hostname") or d.get("ip") or "unknown"),
                ("type", d.get("device_type") or "unknown"),
            ]
        )
        lines.append(f"mynes_device_up{labels} {1 if _is_online(d) else 0}")

    # Per-device response time, only where one exists.
    lines.append("# HELP mynes_device_response_ms Last measured response time in milliseconds.")
    lines.append("# TYPE mynes_device_response_ms gauge")
    for d in devices:
        rt = _response_ms(d)
        if rt is None:
            continue
        labels = _labels(
            [
                ("ip", d.get("ip") or ""),
                ("mac", d.get("mac") or ""),
                ("name", d.get("alias") or d.get("hostname") or d.get("ip") or "unknown"),
                ("type", d.get("device_type") or "unknown"),
            ]
        )
        lines.append(f"mynes_device_response_ms{labels} {rt}")

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# InfluxDB line protocol (push)
# ---------------------------------------------------------------------------


def _esc_tag(value) -> str:
    """Escape an InfluxDB tag key/value or measurement: comma, space, equals."""
    return (
        str(value if value not in (None, "") else "unknown")
        .replace("\\", "\\\\")
        .replace(",", "\\,")
        .replace(" ", "\\ ")
        .replace("=", "\\=")
    )


def influx_line_protocol(devices: list, alerts: list, ts: int | None = None) -> str:
    """Render the current state as InfluxDB line protocol.

    ``ts`` is a unix timestamp in seconds; pass it in to keep this builder pure
    (the caller does ``int(time.time())``). Emits one ``mynes_scan`` aggregate
    line plus one ``mynes_device`` line per device.
    """
    devices = [d for d in (devices or []) if isinstance(d, dict)]
    alerts = [a for a in (alerts or []) if isinstance(a, dict)]
    ts = int(ts if ts is not None else time.time())

    online = sum(1 for d in devices if _is_online(d))
    total = len(devices)
    by_sev = {s: 0 for s in SEVERITIES}
    for a in alerts:
        by_sev[_severity(a)] += 1

    lines: list[str] = []

    scan_fields = [
        f"devices_total={total}i",
        f"devices_online={online}i",
        f"devices_offline={total - online}i",
        f"alerts_total={len(alerts)}i",
    ] + [f"alerts_{s}={by_sev[s]}i" for s in SEVERITIES]
    lines.append(f"mynes_scan {','.join(scan_fields)} {ts}")

    for d in devices:
        tags = ",".join(
            f"{k}={_esc_tag(v)}"
            for k, v in (
                ("ip", d.get("ip") or "unknown"),
                ("name", d.get("alias") or d.get("hostname") or d.get("ip") or "unknown"),
                ("type", d.get("device_type") or "unknown"),
            )
        )
        fields = [f"up={1 if _is_online(d) else 0}i"]
        rt = _response_ms(d)
        if rt is not None:
            fields.append(f"response_ms={rt}")
        lines.append(f"mynes_device,{tags} {','.join(fields)} {ts}")

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Config resolution + push
# ---------------------------------------------------------------------------


def resolve_config() -> dict:
    """InfluxDB/Prometheus settings from data/monitoring.json, env wins.

    The token is read from the env or the local (gitignored) monitoring.json
    only - never config.json. Returns a plain dict; callers decide what to do
    with a missing url/token.
    """
    settings = load_local(SETTINGS_FILE)
    metrics = settings.get("metrics") if isinstance(settings, dict) else None
    metrics = metrics if isinstance(metrics, dict) else {}

    def pick(env_name, key, default=None):
        return os.environ.get(env_name) or metrics.get(key) or default

    enabled = metrics.get("enabled", False)
    if os.environ.get("MYNES_INFLUX_URL") or os.environ.get("MYNES_INFLUX_TOKEN"):
        # An env-configured endpoint is implicitly on unless the file says off.
        enabled = metrics.get("enabled", True)

    prom_env = os.environ.get("MYNES_PROM_ENABLED")
    prom_enabled = (
        prom_env.lower() in ("1", "true", "yes") if prom_env is not None
        else metrics.get("prometheus_enabled", True)
    )

    return {
        "enabled": bool(enabled),
        "url": (pick("MYNES_INFLUX_URL", "url", "") or "").rstrip("/"),
        "token": pick("MYNES_INFLUX_TOKEN", "token", "") or "",
        "org": pick("MYNES_INFLUX_ORG", "org", "") or "",
        "bucket": pick("MYNES_INFLUX_BUCKET", "bucket", "") or "",
        "prometheus_enabled": bool(prom_enabled),
    }


def influx_configured(config: dict | None = None) -> bool:
    config = config or resolve_config()
    return bool(config.get("url") and config.get("token") and config.get("org") and config.get("bucket"))


def push_influx(line: str, config: dict, timeout: float = 5.0) -> tuple[bool, str]:
    """POST line-protocol data to InfluxDB 2. Never raises - returns (ok, msg).

    Mirrors the DiscoveryBackend degrade pattern: any failure (missing config,
    bad URL, HTTP error, timeout) comes back as ``(False, reason)`` so the
    caller can log and carry on.
    """
    url = (config.get("url") or "").rstrip("/")
    token = config.get("token") or ""
    org = config.get("org") or ""
    bucket = config.get("bucket") or ""
    if not (url and token and org and bucket):
        return False, "InfluxDB not configured (need url, token, org, bucket)"

    write_url = (
        f"{url}/api/v2/write?"
        f"org={urllib.parse.quote(org)}&bucket={urllib.parse.quote(bucket)}&precision=s"
    )
    req = urllib.request.Request(
        write_url,
        data=line.encode("utf-8"),
        method="POST",
        headers={
            "Authorization": f"Token {token}",
            "Content-Type": "text/plain; charset=utf-8",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            code = resp.getcode()
        return True, f"wrote {line.count(chr(10))} points (HTTP {code})"
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = e.read().decode("utf-8", "replace")[:200]
        except Exception:  # noqa: BLE001
            pass
        return False, f"HTTP {e.code} {e.reason}: {detail}".strip()
    except (urllib.error.URLError, OSError, ValueError) as e:
        return False, f"{type(e).__name__}: {e}"


def demo():
    """Self-check: builders produce well-formed output, push degrades cleanly."""
    devices = [
        {"ip": "192.168.1.10", "mac": "AA:BB:CC:00:11:22", "alias": "Pi 4",
         "device_type": "Server", "status": "online", "response_time": 3.2},
        {"ip": "192.168.1.20", "hostname": "printer, back office", "device_type": "Printer",
         "status": "offline"},
    ]
    alerts = [{"severity": "critical"}, {"severity": "warning"}, {"severity": "high"}]

    text = prometheus_text(devices, alerts)
    for name in (
        "mynes_devices_total", "mynes_devices_online", "mynes_devices_offline",
        "mynes_alerts_total", "mynes_alerts_by_severity", "mynes_device_up",
        "mynes_device_response_ms",
    ):
        assert name in text, f"missing metric {name}\n{text}"
    assert "# HELP mynes_devices_total" in text
    assert "# TYPE mynes_devices_total gauge" in text
    assert "mynes_devices_total 2" in text
    assert "mynes_devices_online 1" in text
    assert "mynes_devices_offline 1" in text
    # warning normalises to medium, so medium bucket has the mapped one.
    assert 'mynes_alerts_by_severity{severity="critical"} 1' in text
    assert 'mynes_alerts_by_severity{severity="high"} 1' in text
    # response_ms only for the device that has one.
    assert text.count("mynes_device_response_ms{") == 1, text
    # Every non-comment data line must terminate with a newline (already true) and
    # every metric line has balanced braces.
    for ln in text.splitlines():
        if ln and not ln.startswith("#"):
            assert ln.count("{") == ln.count("}"), ln

    line = influx_line_protocol(devices, alerts, ts=1700000000)
    assert line.startswith("mynes_scan "), line
    assert "devices_total=2i" in line
    assert "alerts_critical=1i" in line
    # Tag keys must never contain a space (would corrupt line protocol parsing).
    for ln in line.splitlines():
        if ln.startswith("mynes_device,"):
            tagpart = ln.split(" ", 1)[0].split(",", 1)[1]
            for pair in tagpart.split(","):
                key = pair.split("=", 1)[0]
                assert " " not in key, f"space in tag key: {pair}"
    # The escaped hostname "printer, back office" must not break tag structure:
    # its space and comma are backslash-escaped, not raw.
    assert "printer\\,\\ back\\ office" in line, line
    assert line.rstrip().endswith("1700000000")

    # push_influx never raises and returns (False, ...) for a bad/empty endpoint.
    ok, msg = push_influx("mynes_scan devices_total=0i", {})
    assert ok is False and msg
    ok, msg = push_influx(
        "mynes_scan devices_total=0i",
        {"url": "http://127.0.0.1:1", "token": "x", "org": "o", "bucket": "b"},
        timeout=0.5,
    )
    assert ok is False and msg

    # Config resolver returns the expected shape and never leaks a token by
    # default (no env, no file -> empty).
    cfg = resolve_config()
    assert set(cfg) >= {"enabled", "url", "token", "org", "bucket", "prometheus_enabled"}

    print("metrics demo OK")


if __name__ == "__main__":
    demo()
