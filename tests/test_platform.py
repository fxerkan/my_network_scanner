"""Platform integration: privileges, background service, tray icon.

These must not install anything or run a privileged command. Everything here is
plan/render/parse level; the install paths were verified by hand against a real
launchd agent (installed, served, uninstalled, port released).
"""

import sys

import pytest

from mynes.platform import privileges, service


def test_privileges_self_check():
    privileges.demo()


def test_service_self_check():
    service.demo()


def test_privilege_plan_is_never_a_dead_end():
    """Whatever the platform, the user must be told what to do next."""
    for builder in (privileges._linux_plan, privileges._macos_plan, privileges._windows_plan):
        plan = builder()
        assert plan.summary
        assert plan.commands or plan.notes, f"{builder.__name__} offers no way forward"


def test_apply_is_inert_without_explicit_request():
    result = privileges.apply(privileges.plan(), dry_run=True)
    assert result["changed"] is False


def test_service_launches_the_venv_interpreter_not_the_base_one():
    """Regression: os.path.realpath() resolved the venv symlink to the base
    interpreter, where mynes is not installed, so the service exited 1 forever."""
    assert service._python() == sys.executable


def test_service_env_carries_only_mynes_settings():
    env = service._env()
    assert "MYNES_HOME" in env
    assert all(k.startswith("MYNES_") for k in env), env


def test_launchctl_output_parsing():
    """`launchctl list` exits 0 for a dead job, so status is read from the PID."""
    alive = '{\n\t"PID" = 1234;\n\t"LastExitStatus" = 0;\n}'
    dead = '{\n\t"LastExitStatus" = 256;\n}'
    assert service._plist_field(alive, "PID") == "1234"
    assert service._plist_field(dead, "PID") is None
    assert service._plist_field(dead, "LastExitStatus") == "256"


pystray = pytest.importorskip("pystray", reason="tray is an optional extra")


def test_tray_self_check():
    from mynes import tray

    tray.demo()


def test_tray_severity_ordering():
    """A critical alert must outrank a plain unread count in the icon colour."""
    from mynes.tray import TrayApp

    app = TrayApp("http://127.0.0.1:1")
    app.health = {"alerts": {"unread": 9, "by_severity": {"critical": 0}}}
    assert app.state() == "warning"
    app.health = {"alerts": {"unread": 1, "by_severity": {"critical": 1}}}
    assert app.state() == "critical"
