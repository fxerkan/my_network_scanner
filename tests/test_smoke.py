"""Smoke tests: the package imports, paths resolve, and the web app serves.

These are deliberately cheap - they catch the failure mode that actually bites
after a refactor (a broken import or a path that only worked from the repo root),
not scanner behaviour, which needs a real network.
"""

import pytest

from mynes import paths


def test_paths_resolve_off_package_not_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert paths.CONFIG_DIR.is_absolute()
    assert paths.TEMPLATES_DIR.joinpath("index.html").exists()
    assert paths.LOCALES_DIR.joinpath("tr", "translations.json").exists()


@pytest.mark.parametrize(
    "module",
    [
        "mynes.core.config",
        "mynes.core.models",
        "mynes.core.network",
        "mynes.core.version",
        "mynes.analysis.oui",
        "mynes.analysis.identifier",
        "mynes.security.sanitizer",
        "mynes.integrations.docker",
        "mynes.discovery.mdns",
        "mynes.discovery.ssdp",
        "mynes.monitoring.rules",
        "mynes.monitoring.notify",
    ],
)
def test_module_imports(module):
    __import__(module)


@pytest.fixture(scope="module")
def client():
    """A client with the login gate off.

    The gate is a persisted setting, so whatever state the developer's machine
    is in must not decide whether these tests pass. test_auth.py covers the
    gate itself.
    """
    from mynes.web import auth
    from mynes.web.app import app

    # The setting now lives in data/security.json; patch the reader rather than
    # writing to the developer's own file.
    original = auth.login_required
    auth.login_required = lambda *_: False

    app.config["TESTING"] = True
    try:
        with app.test_client() as c:
            yield c
    finally:
        auth.login_required = original


@pytest.mark.parametrize("route", ["/", "/config", "/history", "/api/version", "/get_devices"])
def test_routes_render(client, route):
    assert client.get(route).status_code == 200


def test_config_json_has_no_plaintext_password():
    """config/config.json is tracked in git - a secret must never live there."""
    import json

    cfg = json.loads((paths.CONFIG_DIR / "config.json").read_text())
    assert not cfg.get("security_settings", {}).get("master_password")


def test_arp_parsing_self_check():
    from mynes.core import arp

    arp.demo()


def test_capabilities_endpoint(client):
    data = client.get("/api/capabilities").get_json()
    # A superset, not an exact match: /api/capabilities is meant to grow as
    # new capability gaps are reported through it.
    assert {"raw_sockets", "nmap", "protocols"} <= set(data)
    assert isinstance(data["raw_sockets"]["available"], bool)
    # Every claim must come with a human-readable reason, not a bare bool.
    assert data["raw_sockets"]["detail"] and data["nmap"]["detail"]


def test_release_bump_rules():
    """Version policy: SemVer from commit type, no release for docs/tests-only."""
    import importlib.util
    import pathlib

    path = pathlib.Path(__file__).resolve().parent.parent / "scripts" / "release_bump.py"
    spec = importlib.util.spec_from_file_location("release_bump", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.demo()
