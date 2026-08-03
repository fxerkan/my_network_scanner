"""Notification channels. stdlib only - urllib for HTTP, smtplib for mail.

Every channel is configured from the same dict shape so the UI can render them
generically:

    {"type": "ntfy", "enabled": true, "min_severity": "warning", ...}

Adding a channel means adding one function to `SENDERS`.
"""

from __future__ import annotations

import json
import logging
import smtplib
import ssl
import urllib.error
import urllib.parse
import urllib.request
from email.message import EmailMessage

from mynes.monitoring.rules import SEVERITIES

log = logging.getLogger(__name__)

TIMEOUT = 10

SEVERITY_EMOJI = {"info": "ℹ️", "warning": "⚠️", "critical": "🚨"}
NTFY_PRIORITY = {"info": "low", "warning": "default", "critical": "urgent"}


def _post(url, data=None, headers=None, method="POST"):
    body = None
    if data is not None:
        body = data if isinstance(data, bytes) else json.dumps(data).encode()
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    if body and "Content-Type" not in (headers or {}):
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:  # noqa: S310 - user-configured URL
        return resp.status, resp.read(2048).decode("utf-8", "replace")


def send_webhook(cfg, alert):
    """Generic JSON POST. Works as-is for Slack/Discord/n8n/Home Assistant webhooks."""
    url = cfg["url"]
    payload = {
        **alert,
        # Slack and Discord both render a bare `text`/`content` field.
        "text": f"{SEVERITY_EMOJI.get(alert['severity'], '')} {alert['title']}\n{alert['message']}",
        "content": f"{SEVERITY_EMOJI.get(alert['severity'], '')} {alert['title']}\n{alert['message']}",
    }
    return _post(url, payload, cfg.get("headers"))


def send_ntfy(cfg, alert):
    """ntfy.sh - the least-friction push channel for phones; no account needed."""
    server = cfg.get("server", "https://ntfy.sh").rstrip("/")
    url = f"{server}/{cfg['topic']}"
    headers = {
        "Title": alert["title"].encode("utf-8").decode("latin-1", "replace"),
        "Priority": NTFY_PRIORITY.get(alert["severity"], "default"),
        "Tags": alert["severity"],
        "Content-Type": "text/plain; charset=utf-8",
    }
    if cfg.get("token"):
        headers["Authorization"] = f"Bearer {cfg['token']}"
    if cfg.get("click_url"):
        headers["Click"] = cfg["click_url"]
    return _post(url, alert["message"].encode("utf-8"), headers)


def send_telegram(cfg, alert):
    text = (
        f"{SEVERITY_EMOJI.get(alert['severity'], '')} *{alert['title']}*\n"
        f"{alert['message']}"
    )
    url = f"https://api.telegram.org/bot{cfg['bot_token']}/sendMessage"
    data = urllib.parse.urlencode(
        {"chat_id": cfg["chat_id"], "text": text, "parse_mode": "Markdown"}
    ).encode()
    return _post(url, data, {"Content-Type": "application/x-www-form-urlencoded"})


def send_smtp(cfg, alert):
    msg = EmailMessage()
    msg["Subject"] = f"[MyNeS {alert['severity'].upper()}] {alert['title']}"
    msg["From"] = cfg["from"]
    msg["To"] = ", ".join(cfg["to"]) if isinstance(cfg["to"], list) else cfg["to"]
    msg.set_content(
        f"{alert['message']}\n\n"
        f"Device : {alert.get('device_name') or '-'}\n"
        f"IP     : {alert.get('ip') or '-'}\n"
        f"MAC    : {alert.get('mac') or '-'}\n"
        f"Rule   : {alert['rule']}\n"
        f"Time   : {alert['timestamp']}\n"
    )

    port = int(cfg.get("port", 587))
    context = ssl.create_default_context()
    if port == 465:
        server = smtplib.SMTP_SSL(cfg["host"], port, timeout=TIMEOUT, context=context)
    else:
        server = smtplib.SMTP(cfg["host"], port, timeout=TIMEOUT)
    with server:
        if port != 465 and cfg.get("starttls", True):
            server.starttls(context=context)
        if cfg.get("username"):
            server.login(cfg["username"], cfg["password"])
        server.send_message(msg)
    return 250, "sent"


SENDERS = {
    "webhook": send_webhook,
    "slack": send_webhook,
    "discord": send_webhook,
    "ntfy": send_ntfy,
    "telegram": send_telegram,
    "smtp": send_smtp,
    "email": send_smtp,
}


def _passes(cfg, alert) -> bool:
    if not cfg.get("enabled", True):
        return False
    minimum = cfg.get("min_severity", "info")
    try:
        if SEVERITIES.index(alert["severity"]) < SEVERITIES.index(minimum):
            return False
    except ValueError:
        pass
    rules = cfg.get("rules")
    return not rules or alert["rule"] in rules


def dispatch(channels: list[dict], alerts: list[dict]) -> list[dict]:
    """Send each alert to every matching channel. Never raises.

    Returns one result row per (channel, alert) attempt so the UI can show
    which delivery failed and why.
    """
    results = []
    for cfg in channels or []:
        sender = SENDERS.get(cfg.get("type"))
        if sender is None:
            log.warning("unknown notification channel type: %r", cfg.get("type"))
            continue
        for alert in alerts:
            if not _passes(cfg, alert):
                continue
            row = {"channel": cfg.get("name") or cfg["type"], "rule": alert["rule"]}
            try:
                status, _ = sender(cfg, alert)
                row.update(ok=True, status=status)
            except (urllib.error.URLError, OSError, smtplib.SMTPException, KeyError) as e:
                log.warning("notification via %s failed: %s", cfg.get("type"), e)
                row.update(ok=False, error=f"{type(e).__name__}: {e}")
            results.append(row)
    return results


def test_channel(cfg: dict) -> dict:
    """Send a probe alert so users can verify a channel from the settings UI."""
    from mynes.monitoring.rules import Alert

    probe = Alert(
        rule="test",
        severity="info",
        title="MyNeS test notification",
        message="If you can read this, the channel is configured correctly.",
    ).to_dict()
    sender = SENDERS.get(cfg.get("type"))
    if sender is None:
        return {"ok": False, "error": f"unknown channel type {cfg.get('type')!r}"}
    try:
        status, body = sender({**cfg, "enabled": True, "min_severity": "info"}, probe)
        return {"ok": True, "status": status, "response": body[:500]}
    except Exception as e:  # noqa: BLE001 - surfaced to the user verbatim
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


def demo():
    """Self-check for the filtering logic - no network calls."""
    a_info = {"severity": "info", "rule": "new_device"}
    a_crit = {"severity": "critical", "rule": "low_voltage"}
    assert _passes({"min_severity": "info"}, a_info)
    assert not _passes({"min_severity": "warning"}, a_info)
    assert _passes({"min_severity": "warning"}, a_crit)
    assert not _passes({"enabled": False}, a_crit)
    assert _passes({"rules": ["low_voltage"]}, a_crit)
    assert not _passes({"rules": ["new_device"]}, a_crit)
    assert dispatch([{"type": "nope"}], [a_crit]) == []
    print("notify demo OK")


if __name__ == "__main__":
    demo()
