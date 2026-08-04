"""Optional login gate.

MyNeS lists every device on a home network, so leaving it open on the LAN hands
that map to anyone who can reach the port. This adds a single-user session
login, off by default (so existing installs do not lock themselves out) and
switchable from the Settings page.

Design notes, because this is a security boundary:

- Credentials come from the environment (`.env`, gitignored, mode 600) and are
  NEVER written to `config/config.json`, which is tracked in git. Only the
  on/off flag lives in the config file.
- The stored password may be a plaintext value or a PBKDF2 hash
  (`pbkdf2_sha256$iterations$salt$hash`). Comparison is constant-time either way.
- Failed attempts are rate limited per client address, so an open LAN port is
  not a free brute-force oracle.
- Turning the gate ON with no credentials configured would lock everyone out,
  so that is refused.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import time
from datetime import timedelta
from functools import wraps

from flask import (
    Blueprint,
    current_app,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

USER_VARS = ("MYNES_AUTH_USERNAME", "MYNES_USERNAME")
PASS_VARS = ("MYNES_AUTH_PASSWORD", "MYNES_PASSWORD_HASH")

SESSION_KEY = "mynes_user"
REMEMBER_DAYS = 30

MAX_ATTEMPTS = 8
LOCKOUT_SECONDS = 300

# Reachable without a session. Everything else is gated.
PUBLIC_ENDPOINTS = {"auth.login", "auth.logout", "static", "static_files", "favicon", "manifest", "service_worker"}
PUBLIC_PATHS = ("/static/", "/favicon.ico", "/manifest.webmanifest", "/service-worker.js")

_attempts: dict[str, list[float]] = {}


# ---------------------------------------------------------------------------
# Password handling
# ---------------------------------------------------------------------------

def hash_password(password: str, iterations: int = 200_000) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return "pbkdf2_sha256${}${}${}".format(
        iterations,
        base64.b64encode(salt).decode(),
        base64.b64encode(digest).decode(),
    )


def verify_password(password: str, stored: str) -> bool:
    """Constant-time check against either a PBKDF2 hash or a plaintext value."""
    if not stored:
        return False
    if stored.startswith("pbkdf2_sha256$"):
        try:
            _, iterations, salt_b64, digest_b64 = stored.split("$", 3)
            digest = hashlib.pbkdf2_hmac(
                "sha256", password.encode(), base64.b64decode(salt_b64), int(iterations)
            )
            return hmac.compare_digest(digest, base64.b64decode(digest_b64))
        except (ValueError, TypeError):
            return False
    return hmac.compare_digest(password.encode(), stored.encode())


def _env(names) -> str | None:
    for name in names:
        if os.environ.get(name):
            return os.environ[name]
    return None


def credentials() -> tuple[str | None, str | None]:
    return _env(USER_VARS), _env(PASS_VARS)


def credentials_configured() -> bool:
    user, password = credentials()
    return bool(user and password)


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

def _client_key() -> str:
    return request.remote_addr or "unknown"


def _recent_failures(key: str) -> list[float]:
    now = time.time()
    kept = [t for t in _attempts.get(key, []) if now - t < LOCKOUT_SECONDS]
    _attempts[key] = kept
    return kept


def locked_out() -> int:
    """Seconds remaining in the lockout, or 0."""
    failures = _recent_failures(_client_key())
    if len(failures) < MAX_ATTEMPTS:
        return 0
    return int(LOCKOUT_SECONDS - (time.time() - min(failures))) or 1


def record_failure() -> None:
    _attempts.setdefault(_client_key(), []).append(time.time())


def clear_failures() -> None:
    _attempts.pop(_client_key(), None)


# ---------------------------------------------------------------------------
# Blueprint
# ---------------------------------------------------------------------------

def create_auth(config_manager) -> Blueprint:
    bp = Blueprint("auth", __name__)

    def enabled() -> bool:
        try:
            settings = (config_manager.config or {}).get("security_settings", {}) or {}
        except Exception:  # noqa: BLE001
            return False
        return bool(settings.get("login_required")) and credentials_configured()

    bp.login_enabled = enabled  # exposed for the settings API

    @bp.route("/login", methods=["GET", "POST"])
    def login():
        if not enabled():
            return redirect(url_for("index"))
        if session.get(SESSION_KEY):
            return redirect(request.args.get("next") or url_for("index"))

        error = None
        if request.method == "POST":
            wait = locked_out()
            if wait:
                error = f"Too many failed attempts. Try again in {wait // 60 + 1} minute(s)."
            else:
                user, stored = credentials()
                form_user = (request.form.get("username") or "").strip()
                ok_user = hmac.compare_digest(form_user.encode(), (user or "").encode())
                ok_pass = verify_password(request.form.get("password") or "", stored or "")
                # Both checks always run: short-circuiting leaks whether the
                # username exists through response timing.
                if ok_user and ok_pass:
                    clear_failures()
                    session.clear()
                    session[SESSION_KEY] = form_user
                    if request.form.get("remember"):
                        session.permanent = True
                        current_app.permanent_session_lifetime = timedelta(days=REMEMBER_DAYS)
                    else:
                        session.permanent = False
                    return redirect(_safe_next(request.form.get("next")))
                record_failure()
                error = "Wrong username or password."

        return render_template(
            "login.html",
            error=error,
            next=_safe_next(request.args.get("next")),
            remember_days=REMEMBER_DAYS,
        ), (401 if error else 200)

    @bp.route("/logout", methods=["GET", "POST"])
    def logout():
        session.clear()
        return redirect(url_for("auth.login") if enabled() else url_for("index"))

    return bp


def _safe_next(target: str | None) -> str:
    """Only allow same-site relative redirects - never an absolute URL.

    Without this, `/login?next=https://evil.example` turns the login page into
    an open redirect.
    """
    if not target or not target.startswith("/") or target.startswith("//"):
        return "/"
    return target


def install(app, config_manager) -> Blueprint:
    """Register the blueprint and the request guard."""
    bp = create_auth(config_manager)
    app.register_blueprint(bp)

    # Session cookies must not be readable by scripts or sent cross-site.
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=request_is_https_default(),
    )

    @app.before_request
    def require_login():
        if not bp.login_enabled():
            return None
        if session.get(SESSION_KEY):
            return None
        if request.endpoint in PUBLIC_ENDPOINTS or request.path.startswith(PUBLIC_PATHS):
            return None
        # Health has to stay reachable for Docker/k8s probes and the tray icon,
        # but it must not leak counts to an unauthenticated caller.
        if request.path == "/api/health":
            return jsonify({"status": "ok", "login_required": True})
        if request.path.startswith("/api/"):
            return jsonify({"error": "authentication required", "login_url": "/login"}), 401
        return redirect(url_for("auth.login", next=request.full_path.rstrip("?")))

    return bp


def request_is_https_default() -> bool:
    """Secure cookies only when the deployment is actually HTTPS.

    A LAN install is plain http://, and setting Secure there would silently
    break every login.
    """
    return os.environ.get("MYNES_HTTPS", "").lower() in ("1", "true", "yes")


def demo():
    """Self-check for the password and redirect logic - no Flask context."""
    h = hash_password("correct horse", iterations=1000)
    assert h.startswith("pbkdf2_sha256$1000$")
    assert verify_password("correct horse", h)
    assert not verify_password("wrong", h)
    assert not verify_password("", h)
    assert not verify_password("x", "")

    # Plaintext values still work, so a .env with a bare password is valid.
    assert verify_password("hunter2", "hunter2")
    assert not verify_password("hunter3", "hunter2")

    # Two hashes of the same password must differ (salted).
    assert hash_password("a", 1000) != hash_password("a", 1000)

    # Open-redirect guard.
    assert _safe_next("/alerts") == "/alerts"
    assert _safe_next("https://evil.example") == "/"
    assert _safe_next("//evil.example") == "/"
    assert _safe_next(None) == "/"
    print("auth demo OK")


if __name__ == "__main__":
    import sys

    if "--hash" in sys.argv:
        import getpass

        print(hash_password(getpass.getpass("Password: ")))
    else:
        demo()
