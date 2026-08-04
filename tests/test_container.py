"""The container-install regressions found on a CasaOS box, pinned.

Every one of these shipped broken in 1.3.0 and every one of them is invisible
on a dev machine, which is exactly why they need a test.
"""

import json

import pytest

from mynes.core import network
from mynes.integrations import docker as docker_mod
from mynes.platform import service
from mynes.web import auth


# --- container detection ----------------------------------------------------

def test_cgroup_v2_host_is_not_mistaken_for_a_container(monkeypatch):
    """cgroup v2 writes "0::/" inside and outside alike."""
    monkeypatch.setattr(network.os.path, "exists", lambda p: False)
    monkeypatch.setattr(network.os.environ, "get", lambda *a: None)
    monkeypatch.setattr("builtins.open", lambda *a, **k: _fake_file("0::/\n"))
    assert network.is_container() is False


def test_docker_marker_file_detects_container_under_cgroup_v2(monkeypatch):
    monkeypatch.setattr(network.os.path, "exists", lambda p: p == "/.dockerenv")
    assert network.is_container() is True


class _fake_file:
    def __init__(self, content):
        self.content = content

    def read(self):
        return self.content

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


# --- docker socket ----------------------------------------------------------

def test_socket_path_is_set_before_availability_is_checked():
    """__init__ used to probe the socket before assigning the path, so the
    AttributeError was swallowed and Docker reported "not installed"."""
    manager = docker_mod.DockerManager()
    assert manager.docker_socket_path


def test_socket_check_requires_write_access(tmp_path, monkeypatch):
    """connect() on a unix socket needs W_OK; R_OK alone let a container that
    could never talk to the daemon believe it could."""
    manager = docker_mod.DockerManager()
    manager.docker_socket_path = str(tmp_path / "sock")
    (tmp_path / "sock").write_text("")
    monkeypatch.setattr(
        docker_mod.os, "access", lambda p, mode: mode == docker_mod.os.R_OK)
    assert manager._check_docker_socket() is False


def test_bridge_names_map_interfaces_to_docker_networks(monkeypatch):
    manager = docker_mod.DockerManager()
    monkeypatch.setattr(manager, "_use_docker_socket_api", lambda endpoint: [
        {"Name": "mynes_default", "Id": "abcdef012345aaaa", "Driver": "bridge"},
        {"Name": "custom", "Id": "999", "Driver": "bridge",
         "Options": {"com.docker.network.bridge.name": "br-custom"}},
        {"Name": "hostnet", "Id": "111", "Driver": "host"},
    ])
    names = manager.bridge_interface_names()
    assert names["br-abcdef012345"] == "mynes_default"
    assert names["br-custom"] == "custom"
    assert names["docker0"] == "bridge"
    assert "br-111" not in names  # host driver has no bridge interface


def test_container_names_lose_the_api_slash(monkeypatch):
    manager = docker_mod.DockerManager()
    monkeypatch.setattr(manager, "_use_docker_socket_api", lambda endpoint: [
        {"Id": "0123456789abcdef", "Names": ["/plex"], "Image": "plex:latest",
         "Status": "Up 2 days", "Ports": [{"PrivatePort": 32400, "Type": "tcp"}],
         "NetworkSettings": {"Networks": {"bridge": {"IPAddress": "172.17.0.5"}}}},
    ])
    (container,) = manager._containers_via_socket()
    assert container["name"] == "plex"
    assert container["id"] == "0123456789ab"
    assert container["ip_addresses"][0]["ipv4"] == "172.17.0.5"


# --- interface labelling ----------------------------------------------------

def test_every_docker_bridge_used_to_get_the_same_label():
    from mynes.core.scanner import LANScanner

    scanner = LANScanner.__new__(LANScanner)      # no network access wanted
    scanner._bridge_name_cache = {"br-aaa": "mynes_default"}

    labelled = {
        scanner.local_interface_label({"interface_type": "Docker", "interface_name": name})
        for name in ("br-aaa", "br-bbb", "docker0")
    }
    assert len(labelled) == 3, "docker bridges must not collapse to one name"
    assert "docker: mynes_default" in labelled
    assert "br-bbb" in labelled          # unknown network falls back to the iface


def test_non_docker_interfaces_keep_their_type():
    from mynes.core.scanner import LANScanner

    scanner = LANScanner.__new__(LANScanner)
    scanner._bridge_name_cache = {}
    assert scanner.local_interface_label(
        {"interface_type": "WiFi", "interface_name": "wlan0"}) == "WiFi"


# --- credentials without a .env ---------------------------------------------

def test_credentials_can_be_set_without_an_env_file(tmp_path, monkeypatch):
    monkeypatch.setenv("MYNES_DATA_DIR", str(tmp_path))
    for var in auth.USER_VARS + auth.PASS_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(auth, "load_local", _local_store(tmp_path))
    monkeypatch.setattr(auth, "save_local", _local_saver(tmp_path))

    assert auth.credentials_source() == "none"
    auth.set_credentials("admin", "a-long-enough-one")
    assert auth.credentials_source() == "stored"

    user, stored = auth.credentials()
    assert user == "admin"
    assert stored.startswith("pbkdf2_sha256$"), "plaintext must never hit disk"
    assert auth.verify_password("a-long-enough-one", stored)
    assert not auth.verify_password("wrong", stored)


def test_toggle_does_not_wipe_stored_credentials(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "load_local", _local_store(tmp_path))
    monkeypatch.setattr(auth, "save_local", _local_saver(tmp_path))
    auth.set_credentials("admin", "a-long-enough-one")
    auth.set_login_required(True)
    assert auth.load_local(auth.SECURITY_FILE)["username"] == "admin"


def test_short_passwords_are_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "load_local", _local_store(tmp_path))
    monkeypatch.setattr(auth, "save_local", _local_saver(tmp_path))
    with pytest.raises(ValueError):
        auth.set_credentials("admin", "short")


def _local_store(tmp_path):
    def load(name):
        path = tmp_path / name
        return json.loads(path.read_text()) if path.exists() else {}
    return load


def _local_saver(tmp_path):
    def save(name, data):
        (tmp_path / name).write_text(json.dumps(data))
        return data
    return save


# --- background service -----------------------------------------------------

def test_service_install_does_not_reach_for_systemctl_in_a_container(monkeypatch):
    """The Install button ran the Linux path and crashed on missing systemctl."""
    monkeypatch.setattr(service, "is_container", lambda: True)
    result = service.install()
    assert result["ok"] is True
    assert result["supported"] is False
    assert "container" in result["detail"].lower()


# --- store placeholders -----------------------------------------------------

def test_unsubstituted_manifest_placeholder_is_dropped(monkeypatch):
    """`TZ: $TZ` in a store manifest is not always filled in; the literal
    reaching the process silently reads as UTC."""
    import mynes

    monkeypatch.setenv("TZ", "$TZ")
    monkeypatch.setenv("MYNES_PORT", "${MYNES_PORT}")
    monkeypatch.setenv("MYNES_HA_URL", "http://homeassistant.local:8123")
    monkeypatch.setenv("MYNES_MQTT_PASSWORD", "$ecret-but-real")

    dropped = mynes.drop_unsubstituted_env()

    assert "TZ" in dropped and "MYNES_PORT" in dropped
    assert mynes.os.environ.get("MYNES_HA_URL") == "http://homeassistant.local:8123"
    # A password that merely starts with $ is a value, not a placeholder.
    assert mynes.os.environ.get("MYNES_MQTT_PASSWORD") == "$ecret-but-real"
