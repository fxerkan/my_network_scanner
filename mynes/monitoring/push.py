"""MyNeS's own push channel — Web Push straight to the browser or the PWA.

No Home Assistant, no third-party relay: the alert goes from this process to
the user's device via the browser vendor's push service, which is the only hop
a web app is allowed to use. That makes it the answer to "can MyNeS notify me
without Home Assistant" — yes, on any device where the user has granted the
notification permission once.

    config/.vapid_key            the VAPID private key, mode 600, gitignored
    data/push_subscriptions.json the devices that opted in

Phase 2's mobile app will *not* use Web Push — a React Native build registers
an Expo/FCM token instead — so a subscription is stored as an opaque record
with a `kind` field, and `send()` dispatches on that. Adding "expo" later means
adding one function, not reshaping the store.

`pywebpush` is optional: without it this module reports itself unavailable and
every other channel keeps working.

    python -m mynes.monitoring.push        # self-check
"""

from __future__ import annotations

import json
import logging
import os
import time

from mynes.paths import config_file, data_file

log = logging.getLogger(__name__)

SUBSCRIPTIONS_FILE = "push_subscriptions.json"
VAPID_KEY_FILE = ".vapid_key"

# Identifies this server to the push service. Not a contact channel anyone
# reads; the spec just requires *something* stable.
VAPID_CLAIM_SUBJECT = "mailto:mynes@localhost"

SEVERITY_ICON = {"info": "i-info", "warning": "i-alert", "critical": "i-alert"}


def available() -> tuple[bool, str]:
    """(usable, why not). Same contract as the discovery backends."""
    try:
        import pywebpush  # noqa: F401
    except ImportError:
        return False, "pywebpush is not installed (pip install 'mynes[push]')"
    return True, "ready"


# ------------------------------------------------------------------ VAPID keys

def _load_or_create_vapid():
    """The key pair identifying this server. Generated once, then reused.

    Regenerating it invalidates every existing subscription, which is why it is
    written to disk rather than held in memory.
    """
    from py_vapid import Vapid02

    path = config_file(VAPID_KEY_FILE)
    if os.path.exists(path):
        return Vapid02.from_file(path)

    vapid = Vapid02()
    vapid.generate_keys()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    vapid.save_key(path)
    os.chmod(path, 0o600)          # a private key must not be world-readable
    log.info("generated a new VAPID key pair at %s", path)
    return vapid


def vapid_public_key() -> str | None:
    """base64url public key the browser needs to subscribe. None if unavailable."""
    ok, _ = available()
    if not ok:
        return None
    from cryptography.hazmat.primitives import serialization
    from py_vapid import b64urlencode

    vapid = _load_or_create_vapid()
    raw = vapid.public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    return b64urlencode(raw).decode() if isinstance(b64urlencode(raw), bytes) else b64urlencode(raw)


# ---------------------------------------------------------------- subscriptions

def _store_path() -> str:
    return data_file(SUBSCRIPTIONS_FILE)


def subscriptions() -> list[dict]:
    path = _store_path()
    if not os.path.exists(path):
        return []
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return data.get("subscriptions", [])
    except (OSError, ValueError):
        return []


def _save(subs: list[dict]) -> None:
    path = _store_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"subscriptions": subs}, fh, ensure_ascii=False, indent=2)


def _key_of(sub: dict) -> str:
    """What makes two subscriptions the same device."""
    return sub.get("endpoint") or sub.get("token") or ""


def subscribe(record: dict, label: str | None = None) -> dict:
    """Register a device. Re-subscribing the same endpoint updates it in place."""
    key = _key_of(record)
    if not key:
        raise ValueError("subscription needs an 'endpoint' (web push) or 'token' (mobile)")

    entry = {
        "kind": record.get("kind") or ("webpush" if record.get("endpoint") else "token"),
        "label": label or record.get("label") or "",
        "created": record.get("created") or time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        **{k: v for k, v in record.items() if k in ("endpoint", "keys", "token", "expirationTime")},
    }
    subs = [s for s in subscriptions() if _key_of(s) != key]
    subs.append(entry)
    _save(subs)
    return entry


def unsubscribe(key: str) -> bool:
    subs = subscriptions()
    kept = [s for s in subs if _key_of(s) != key]
    _save(kept)
    return len(kept) != len(subs)


# ---------------------------------------------------------------------- sending

def _payload(alert: dict) -> str:
    return json.dumps(
        {
            "title": alert.get("title") or "MyNeS",
            "body": alert.get("message") or "",
            "severity": alert.get("severity", "info"),
            "rule": alert.get("rule"),
            "ip": alert.get("ip"),
            "mac": alert.get("mac"),
            "timestamp": alert.get("timestamp"),
            "url": "/alerts",
            "icon": SEVERITY_ICON.get(alert.get("severity"), "i-info"),
        }
    )


def send(alert: dict) -> dict:
    """Push one alert to every registered device.

    Subscriptions the push service reports as gone (404/410) are pruned — an
    uninstalled PWA would otherwise fail forever on every single alert.
    """
    ok, reason = available()
    if not ok:
        return {"ok": False, "error": reason, "sent": 0}

    from pywebpush import WebPushException, webpush

    subs = subscriptions()
    if not subs:
        return {"ok": True, "sent": 0, "detail": "no devices registered"}

    # pywebpush takes a Vapid instance, a key file path, or a raw base64 der.
    # Hand it the instance: a PEM *string* goes down the from_string path and
    # fails to deserialize, which is a confusing way to learn this.
    vapid = _load_or_create_vapid()
    payload = _payload(alert)

    sent, failed, dead = 0, [], []
    for sub in subs:
        if sub.get("kind") != "webpush":
            continue                      # a mobile token: not this transport's job yet
        try:
            webpush(
                subscription_info={"endpoint": sub["endpoint"], "keys": sub.get("keys", {})},
                data=payload,
                vapid_private_key=vapid,
                vapid_claims={"sub": VAPID_CLAIM_SUBJECT},
                timeout=10,
            )
            sent += 1
        except WebPushException as e:
            status = getattr(getattr(e, "response", None), "status_code", None)
            if status in (404, 410):
                dead.append(_key_of(sub))
            else:
                failed.append(f"{status or '?'}: {e}")
        except Exception as e:  # noqa: BLE001 - one bad device must not stop the rest
            failed.append(f"{type(e).__name__}: {e}")

    if dead:
        _save([s for s in subs if _key_of(s) not in dead])
        log.info("pruned %d expired push subscription(s)", len(dead))

    return {"ok": not failed, "sent": sent, "pruned": len(dead), "errors": failed}


def demo():
    """Self-check for the store and the payload. No network, no real keys."""
    import tempfile

    from pathlib import Path

    from mynes import paths

    with tempfile.TemporaryDirectory() as tmp:
        original = paths.DATA_DIR
        paths.DATA_DIR = Path(tmp)    # DATA_DIR is resolved at import time

        assert subscriptions() == []

        subscribe({"endpoint": "https://push.example/abc", "keys": {"p256dh": "x", "auth": "y"}}, label="laptop")
        rows = subscriptions()
        assert len(rows) == 1 and rows[0]["kind"] == "webpush" and rows[0]["label"] == "laptop"

        # Re-subscribing the same endpoint updates rather than duplicating.
        subscribe({"endpoint": "https://push.example/abc", "keys": {"p256dh": "z", "auth": "y"}}, label="laptop 2")
        rows = subscriptions()
        assert len(rows) == 1 and rows[0]["keys"]["p256dh"] == "z" and rows[0]["label"] == "laptop 2"

        # A future mobile token is stored side by side, tagged by kind.
        subscribe({"token": "ExponentPushToken[xyz]", "kind": "expo"}, label="phone")
        assert {s["kind"] for s in subscriptions()} == {"webpush", "expo"}

        assert unsubscribe("https://push.example/abc") is True
        assert unsubscribe("https://push.example/abc") is False
        assert len(subscriptions()) == 1

        try:
            subscribe({"label": "nothing"})
            raise AssertionError("a subscription with neither endpoint nor token must be rejected")
        except ValueError:
            pass

        paths.DATA_DIR = original

    body = json.loads(_payload({"title": "New device: pi", "message": "hello", "severity": "warning", "rule": "new_device"}))
    assert body["title"] == "New device: pi" and body["body"] == "hello"
    assert body["url"] == "/alerts" and body["severity"] == "warning"

    print("push demo ok")


if __name__ == "__main__":
    demo()
