"""Metrics export for Grafana - two backends, both optional.

**Prometheus (pull)**: `prometheus_text()` renders the current device/alert state
in the Prometheus text exposition format (v0.0.4). MyNeS exposes it at
`/api/metrics`; point a Prometheus scrape or Grafana Agent at that path and the
dashboards fill themselves. No dependency - it is a string builder.

**InfluxDB 1.x / 2 (push)**: `influx_line_protocol()` renders the same state as
InfluxDB line protocol and `push_influx()` POSTs it over stdlib urllib - to
`/write?db=` on InfluxDB 1.x (database + optional user/password; the database and
its retention policy are created on first write) or to `/api/v2/write` on
InfluxDB 2 (token/org/bucket). `export_scan()` is the single call the monitoring
scheduler and the manual scan threads make after every scan, so a home lab
already running Influx+Grafana gets a time series with no extra moving parts.
`deploy/grafana/` holds a ready dashboard for it.

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
        .replace("\n", " ")
    )


def _esc_field_str(value) -> str:
    """A string *field* value: double-quoted, backslash and quote escaped."""
    text = str(value if value is not None else "").replace("\n", " ")
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _security(device: dict) -> dict | None:
    """The device's stored security assessment, if an analysis produced one.

    Enhanced analysis keeps it under analysis_data.enhanced_analysis_info.
    security_analysis (mirrored into enhanced_comprehensive_info). None when the
    device was never analysed - "no data" must not be exported as "risk 0".
    """
    roots = (
        ((device.get("analysis_data") or {}).get("enhanced_analysis_info") or {}),
        device.get("enhanced_comprehensive_info") or {},
    )
    for root in roots:
        sec = root.get("security_analysis") if isinstance(root, dict) else None
        if isinstance(sec, dict) and ("risk_score" in sec or "findings" in sec):
            return sec
    return None


def _device_name(d: dict) -> str:
    return d.get("alias") or d.get("hostname") or d.get("ip") or d.get("mac") or "unknown"


def _num(value, default=0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def influx_line_protocol(devices: list, alerts: list, ts: int | None = None,
                         uplinks: dict | None = None, duration_s: float | None = None) -> str:
    """Render the current state as InfluxDB line protocol.

    ``ts`` is a unix timestamp in seconds; pass it in to keep this builder pure
    (the caller does ``int(time.time())``). Measurements:

    - ``mynes_scan``      one aggregate point: totals, alert counts by severity,
                          scan duration when known
    - ``mynes_inventory`` one point per (kind, value): device counts by type,
                          vendor and location, ready for a Grafana bar/pie
    - ``mynes_device``    one point per device. Descriptive values are tags (ip,
                          mac, name, type, vendor, location, trust, medium,
                          uplink); ``status`` is a string *field*, not a tag, so a
                          device flapping online/offline stays a single series
    - ``mynes_security``  per analysed device: risk score/level, finding counts
    - ``mynes_alert``     one point per alert passed in (this scan's alerts)
    """
    devices = [d for d in (devices or []) if isinstance(d, dict)]
    alerts = [a for a in (alerts or []) if isinstance(a, dict)]
    uplinks = uplinks or {}
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
    if duration_s is not None:
        scan_fields.append(f"duration_s={round(_num(duration_s), 2)}")
    lines.append(f"mynes_scan {','.join(scan_fields)} {ts}")

    for kind, key in (("type", "device_type"), ("vendor", "vendor"), ("location", "location")):
        counts: dict[str, list[int]] = {}
        for d in devices:
            c = counts.setdefault(d.get(key) or "unknown", [0, 0])
            c[0] += 1
            c[1] += 1 if _is_online(d) else 0
        for val, (n, n_on) in sorted(counts.items()):
            lines.append(
                f"mynes_inventory,kind={kind},value={_esc_tag(val)} count={n}i,online={n_on}i {ts}"
            )

    for d in devices:
        ip = d.get("ip") or ""
        mac = (d.get("mac") or "").lower()
        medium = d.get("connection_medium")
        medium = medium.get("medium") if isinstance(medium, dict) else medium
        tags = ",".join(
            f"{k}={_esc_tag(v)}"
            for k, v in (
                ("ip", ip or "none"),
                ("mac", mac or "none"),
                ("name", _device_name(d)),
                ("type", d.get("device_type") or "unknown"),
                ("vendor", d.get("vendor") or "unknown"),
                ("location", d.get("location") or "unknown"),
                ("trust", d.get("trust_status") or "unknown"),
                ("medium", medium or "unknown"),
                ("uplink", uplinks.get(ip) or uplinks.get(mac) or "auto"),
            )
        )
        up = 1 if _is_online(d) else 0
        ports = d.get("open_ports")
        fields = [
            f"up={up}i",
            f"open_port_count={len(ports) if isinstance(ports, list) else 0}i",
            f"status={_esc_field_str(d.get('status') or 'unknown')}",
        ]
        rt = _response_ms(d)
        if rt is not None:
            fields.append(f"response_ms={rt}")
        sec = _security(d)
        if sec is not None:
            fields.append(f"risk_score={_num(sec.get('risk_score'))}")
        lines.append(f"mynes_device,{tags} {','.join(fields)} {ts}")

        if sec is not None:
            stags = ",".join(
                f"{k}={_esc_tag(v)}"
                for k, v in (
                    ("ip", ip or "none"),
                    ("mac", mac or "none"),
                    ("name", _device_name(d)),
                    ("level", sec.get("risk_level") or "none"),
                )
            )
            findings = sec.get("findings") or []
            exposures = sec.get("exposures") or []
            sevs = {s: 0 for s in ("critical", "high", "medium", "low")}
            for item in list(findings) + list(exposures):
                sv = str(item.get("severity", "")).lower() if isinstance(item, dict) else ""
                if sv in sevs:
                    sevs[sv] += 1
            sfields = [
                f"risk_score={_num(sec.get('risk_score'))}",
                f"findings={len(findings)}i",
                f"exposures={len(exposures)}i",
            ] + [f"{k}={v}i" for k, v in sevs.items()]
            lines.append(f"mynes_security,{stags} {','.join(sfields)} {ts}")

    # Several alerts in one second would share series+timestamp and overwrite
    # each other; a per-scan sequence tag keeps them distinct (bounded: it
    # resets every scan, so cardinality stays at the max alerts per scan).
    for i, a in enumerate(alerts):
        atags = ",".join(
            f"{k}={_esc_tag(v)}"
            for k, v in (
                ("rule", a.get("rule") or "unknown"),
                ("severity", _severity(a)),
                ("device", a.get("device_name") or a.get("ip") or a.get("mac") or "unknown"),
                ("seq", i),
            )
        )
        lines.append(f"mynes_alert,{atags} count=1i,title={_esc_field_str(a.get('title') or '')} {ts}")

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Config resolution + push
# ---------------------------------------------------------------------------


def resolve_config() -> dict:
    """InfluxDB/Prometheus settings from data/monitoring.json, env wins.

    Secrets (v2 token, v1 password) come from the env or the local, gitignored
    monitoring.json only - never config.json. ``version`` is "1" or "2"; when
    unset it is inferred: a token/org/bucket means InfluxDB 2, otherwise 1.x.
    """
    settings = load_local(SETTINGS_FILE)
    metrics = settings.get("metrics") if isinstance(settings, dict) else None
    metrics = metrics if isinstance(metrics, dict) else {}

    def pick(env_name, key, default=None):
        return os.environ.get(env_name) or metrics.get(key) or default

    enabled = metrics.get("enabled", False)
    if os.environ.get("MYNES_INFLUX_URL"):
        # An env-configured endpoint is implicitly on unless the file says off.
        enabled = metrics.get("enabled", True)

    prom_env = os.environ.get("MYNES_PROM_ENABLED")
    prom_enabled = (
        prom_env.lower() in ("1", "true", "yes") if prom_env is not None
        else metrics.get("prometheus_enabled", True)
    )

    cfg = {
        "enabled": bool(enabled),
        "url": (pick("MYNES_INFLUX_URL", "url", "") or "").rstrip("/"),
        "token": pick("MYNES_INFLUX_TOKEN", "token", "") or "",
        "org": pick("MYNES_INFLUX_ORG", "org", "") or "",
        "bucket": pick("MYNES_INFLUX_BUCKET", "bucket", "") or "",
        "database": pick("MYNES_INFLUX_DB", "database", "mynes") or "mynes",
        "username": pick("MYNES_INFLUX_USER", "username", "") or "",
        "password": pick("MYNES_INFLUX_PASSWORD", "password", "") or "",
        "retention_days": int(_num(pick("MYNES_INFLUX_RETENTION_DAYS", "retention_days", 400), 400)),
        "prometheus_enabled": bool(prom_enabled),
    }
    version = str(pick("MYNES_INFLUX_VERSION", "version", "") or "")
    if version not in ("1", "2"):
        version = "2" if (cfg["token"] and cfg["org"] and cfg["bucket"]) else "1"
    cfg["version"] = version
    return cfg


def influx_configured(config: dict | None = None) -> bool:
    config = config or resolve_config()
    if not config.get("url"):
        return False
    if config.get("version") == "2":
        return bool(config.get("token") and config.get("org") and config.get("bucket"))
    return bool(config.get("database"))


def _request(url: str, data: bytes | None, config: dict, timeout: float,
             content_type: str = "text/plain; charset=utf-8"):
    headers = {"Content-Type": content_type}
    if config.get("version") == "2":
        headers["Authorization"] = f"Token {config.get('token') or ''}"
    elif config.get("username"):
        import base64

        cred = f"{config['username']}:{config.get('password') or ''}".encode()
        headers["Authorization"] = "Basic " + base64.b64encode(cred).decode()
    req = urllib.request.Request(url, data=data, method="POST", headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        return resp.getcode(), resp.read()


def _http_error(e: urllib.error.HTTPError) -> str:
    detail = ""
    try:
        detail = e.read().decode("utf-8", "replace")[:200]
    except Exception:  # noqa: BLE001
        pass
    return f"HTTP {e.code} {e.reason}: {detail}".strip()


def ensure_database(config: dict, timeout: float = 5.0) -> tuple[bool, str]:
    """InfluxDB 1.x: create the database and a default retention policy.

    CREATE DATABASE is idempotent on 1.x. The policy is created (or altered to
    the configured duration) as ``mynes_<N>d`` and made the default, so points
    expire on their own instead of growing forever on an SD card / SSD.
    """
    url = (config.get("url") or "").rstrip("/")
    db = config.get("database") or "mynes"
    days = max(1, int(_num(config.get("retention_days"), 400)))
    rp = f"mynes_{days}d"
    stmts = [
        f'CREATE DATABASE "{db}"',
        f'CREATE RETENTION POLICY "{rp}" ON "{db}" DURATION {days}d REPLICATION 1 DEFAULT',
    ]
    try:
        for q in stmts:
            body = urllib.parse.urlencode({"q": q}).encode()
            _request(f"{url}/query", body, config, timeout,
                     content_type="application/x-www-form-urlencoded")
        return True, f"database {db} ready (retention {days}d)"
    except urllib.error.HTTPError as e:
        return False, _http_error(e)
    except (urllib.error.URLError, OSError, ValueError) as e:
        return False, f"{type(e).__name__}: {e}"


def push_influx(line: str, config: dict, timeout: float = 5.0) -> tuple[bool, str]:
    """POST line-protocol data to InfluxDB 1.x or 2. Never raises - (ok, msg).

    Mirrors the DiscoveryBackend degrade pattern: missing config, bad URL, HTTP
    error or timeout all come back as ``(False, reason)``. On 1.x a missing
    database is created (with its retention policy) and the write retried once.
    """
    if not influx_configured(config):
        return False, "InfluxDB not configured (1.x: url + database; 2.x: url, token, org, bucket)"
    url = (config.get("url") or "").rstrip("/")
    points = line.count("\n") or 1

    if config.get("version") == "2":
        write_url = (
            f"{url}/api/v2/write?org={urllib.parse.quote(config['org'])}"
            f"&bucket={urllib.parse.quote(config['bucket'])}&precision=s"
        )
    else:
        write_url = f"{url}/write?db={urllib.parse.quote(config.get('database') or 'mynes')}&precision=s"

    for attempt in (1, 2):
        try:
            code, _ = _request(write_url, line.encode("utf-8"), config, timeout)
            return True, f"wrote {points} points (HTTP {code})"
        except urllib.error.HTTPError as e:
            msg = _http_error(e)
            if (attempt == 1 and config.get("version") != "2" and e.code == 404
                    and "database not found" in msg):
                ok, why = ensure_database(config, timeout)
                if ok:
                    continue
                return False, f"{msg}; create failed: {why}"
            return False, msg
        except (urllib.error.URLError, OSError, ValueError) as e:
            return False, f"{type(e).__name__}: {e}"
    return False, "write failed"


# Last export result, for the settings page and /api/capabilities. Per process,
# which is fine: one MyNeS process does all the writing.
LAST_EXPORT: dict = {"at": None, "ok": None, "msg": "no export yet", "points": 0}


def _uplinks() -> dict:
    try:
        from mynes.core import topology

        return (topology.load_state() or {}).get("uplinks") or {}
    except Exception:  # noqa: BLE001
        return {}


def export_scan(devices: list, alerts: list | None = None, duration_s: float | None = None,
                config: dict | None = None) -> tuple[bool, str]:
    """The one call made after every scan (scheduled or manual). Never raises.

    Returns (False, reason) without touching the network when export is off.
    """
    try:
        cfg = config or resolve_config()
        if not (cfg.get("enabled") and influx_configured(cfg)):
            return False, "InfluxDB export disabled"
        line = influx_line_protocol(devices, alerts or [], ts=int(time.time()),
                                    uplinks=_uplinks(), duration_s=duration_s)
        ok, msg = push_influx(line, cfg)
        LAST_EXPORT.update({
            "at": time.strftime("%Y-%m-%dT%H:%M:%S"), "ok": ok, "msg": msg,
            "points": line.count("\n"),
        })
        if not ok:
            log.warning("InfluxDB export failed: %s", msg)
        return ok, msg
    except Exception as e:  # noqa: BLE001 - an export must never break a scan
        log.warning("InfluxDB export errored: %s", e)
        LAST_EXPORT.update({"at": time.strftime("%Y-%m-%dT%H:%M:%S"), "ok": False,
                            "msg": f"{type(e).__name__}: {e}"})
        return False, str(e)


def demo():
    """Self-check: builders produce well-formed output, push degrades cleanly."""
    devices = [
        {"ip": "192.168.1.10", "mac": "AA:BB:CC:00:11:22", "alias": "Pi 4",
         "device_type": "Server", "status": "online", "response_time": 3.2,
         "vendor": "Raspberry Pi", "location": "Living Room", "trust_status": "trusted",
         "connection_medium": {"medium": "wired"}, "open_ports": [22, 80],
         "analysis_data": {"enhanced_analysis_info": {"security_analysis": {
             "risk_score": 12, "risk_level": "high",
             "findings": [], "exposures": [{"severity": "high", "title": "Telnet"}]}}}},
        {"ip": "192.168.1.20", "hostname": "printer, back office", "device_type": "Printer",
         "status": "offline"},
    ]
    alerts = [{"severity": "critical", "rule": "new_device", "device_name": "x", "title": 'a "q"'},
              {"severity": "warning", "rule": "port_open"}, {"severity": "high"}]

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
    assert 'mynes_alerts_by_severity{severity="critical"} 1' in text
    assert 'mynes_alerts_by_severity{severity="high"} 1' in text
    assert text.count("mynes_device_response_ms{") == 1, text
    for ln in text.splitlines():
        if ln and not ln.startswith("#"):
            assert ln.count("{") == ln.count("}"), ln

    line = influx_line_protocol(devices, alerts, ts=1700000000,
                                uplinks={"192.168.1.10": "192.168.1.1"}, duration_s=12.345)
    assert line.startswith("mynes_scan "), line
    assert "devices_total=2i" in line and "alerts_critical=1i" in line
    assert "duration_s=12.35" in line
    # Tag keys must never contain a space (would corrupt line protocol parsing).
    for ln in line.splitlines():
        measurement_tags = ln.split(" ", 1)[0] if "\\ " not in ln else None
        if ln.startswith("mynes_device,") and measurement_tags:
            for pair in measurement_tags.split(",")[1:]:
                assert " " not in pair.split("=", 1)[0], pair
    # The escaped hostname "printer, back office" must not break tag structure.
    assert "printer\\,\\ back\\ office" in line, line
    assert "uplink=192.168.1.1" in line and "location=Living\\ Room" in line
    assert 'status="online"' in line and "open_port_count=2i" in line
    assert "mynes_inventory,kind=type,value=Server count=1i,online=1i" in line
    assert "mynes_security,ip=192.168.1.10" in line and "level=high" in line
    assert "exposures=1i" in line and "high=1i" in line
    # Never-analysed device: no security point, no risk field.
    assert "mynes_security,ip=192.168.1.20" not in line
    assert line.count("mynes_alert,") == 3 and 'title="a \\"q\\""' in line
    assert line.rstrip().endswith("1700000000")

    # push_influx never raises and returns (False, ...) for a bad/empty endpoint.
    ok, msg = push_influx("mynes_scan devices_total=0i", {})
    assert ok is False and msg
    ok, msg = push_influx(
        "mynes_scan devices_total=0i",
        {"url": "http://127.0.0.1:1", "token": "x", "org": "o", "bucket": "b", "version": "2"},
        timeout=0.5,
    )
    assert ok is False and msg
    ok, msg = push_influx("mynes_scan devices_total=0i",
                          {"url": "http://127.0.0.1:1", "database": "mynes", "version": "1"},
                          timeout=0.5)
    assert ok is False and msg
    # Disabled export is a clean no-op.
    assert export_scan(devices, [], config={"enabled": False})[0] is False

    cfg = resolve_config()
    assert set(cfg) >= {"enabled", "url", "token", "org", "bucket", "prometheus_enabled",
                        "version", "database", "username", "password", "retention_days"}
    assert influx_configured({"url": "http://x", "database": "mynes", "version": "1"})
    assert not influx_configured({"url": "http://x", "version": "2", "token": "t"})

    print("metrics demo OK")


if __name__ == "__main__":
    demo()
