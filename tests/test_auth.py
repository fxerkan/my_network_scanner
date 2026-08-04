"""Login gate. Security boundary, so the guards get explicit tests."""

import pytest

from mynes.web import auth


def test_auth_self_check():
    auth.demo()


def test_hash_roundtrip_and_salting():
    h1 = auth.hash_password("correct horse", iterations=1000)
    h2 = auth.hash_password("correct horse", iterations=1000)
    assert h1 != h2, "hashes must be salted"
    assert auth.verify_password("correct horse", h1)
    assert not auth.verify_password("Correct Horse", h1)
    assert not auth.verify_password("", h1)


def test_plaintext_passwords_still_work():
    """A bare password in .env must work - not everyone will hash one."""
    assert auth.verify_password("hunter2", "hunter2")
    assert not auth.verify_password("hunter3", "hunter2")


def test_empty_stored_password_never_authenticates():
    assert not auth.verify_password("", "")
    assert not auth.verify_password("anything", "")


def test_malformed_hash_is_rejected_not_crashed():
    for broken in ("pbkdf2_sha256$", "pbkdf2_sha256$abc$x$y", "pbkdf2_sha256$1000$!!$!!"):
        assert auth.verify_password("x", broken) is False


@pytest.mark.parametrize(
    "target,expected",
    [
        ("/alerts", "/alerts"),
        ("/config?tab=1", "/config?tab=1"),
        # An open redirect would turn the login page into a phishing hop.
        ("https://evil.example", "/"),
        ("//evil.example", "/"),
        ("http://evil.example", "/"),
        (None, "/"),
        ("", "/"),
    ],
)
def test_next_parameter_cannot_leave_the_site(target, expected):
    assert auth._safe_next(target) == expected


def test_credentials_read_from_either_env_spelling(monkeypatch):
    for var in auth.USER_VARS + auth.PASS_VARS:
        monkeypatch.delenv(var, raising=False)
    assert not auth.credentials_configured()

    monkeypatch.setenv("MYNES_USERNAME", "u")
    monkeypatch.setenv("MYNES_PASSWORD_HASH", "p")
    assert auth.credentials_configured()


def test_gate_cannot_be_enabled_without_credentials(monkeypatch):
    """Turning the gate on with no key would lock everyone out of a LAN app."""
    from mynes.web.app import app

    for var in auth.USER_VARS + auth.PASS_VARS:
        monkeypatch.delenv(var, raising=False)

    with app.test_client() as c:
        r = c.post("/api/auth/status", json={"login_required": True})
        assert r.status_code == 400
        assert not r.get_json()["ok"]


def test_rate_limiting_blocks_after_repeated_failures(monkeypatch):
    from mynes.web.app import app

    auth._attempts.clear()
    with app.test_request_context("/login", environ_base={"REMOTE_ADDR": "10.9.9.9"}):
        assert auth.locked_out() == 0
        for _ in range(auth.MAX_ATTEMPTS):
            auth.record_failure()
        assert auth.locked_out() > 0
        auth.clear_failures()
        assert auth.locked_out() == 0


def test_enabled_gate_redirects_pages_and_401s_the_api(monkeypatch):
    from mynes.web.app import app, scanner

    monkeypatch.setenv("MYNES_AUTH_USERNAME", "tester")
    monkeypatch.setenv("MYNES_AUTH_PASSWORD", "s3cret-pass")
    config = scanner.get_config_manager()
    original = auth.login_required
    auth.login_required = lambda *_: True
    auth._attempts.clear()

    try:
        with app.test_client() as c:
            page = c.get("/alerts")
            assert page.status_code == 302 and "/login" in page.headers["Location"]

            api = c.get("/api/alerts")
            assert api.status_code == 401

            # Health stays reachable for probes but must not leak device counts.
            health = c.get("/api/health").get_json()
            assert health["login_required"] is True
            assert "devices" not in health

            # The login page and the assets it needs stay public.
            assert c.get("/login").status_code == 200
            assert c.get("/static/css/design-system.css").status_code == 200

            assert c.post("/login", data={"username": "tester", "password": "wrong"}).status_code == 401

            ok = c.post("/login", data={"username": "tester", "password": "s3cret-pass", "next": "/alerts"})
            assert ok.status_code == 302 and ok.headers["Location"].endswith("/alerts")
            assert c.get("/api/alerts").status_code == 200
    finally:
        auth.login_required = original
        auth._attempts.clear()
