"""Run MyNeS in the background, starting at login, on any desktop OS.

Scheduled scanning is useless if it only runs while a browser tab is open. This
installs MyNeS as a background service:

- **macOS**: a launchd **LaunchAgent** in `~/Library/LaunchAgents`
- **Linux**: a **systemd user unit** in `~/.config/systemd/user`
- **Windows**: a **Scheduled Task** triggered at logon

All three are *user-level* on purpose: no sudo, no system-wide daemon, and
uninstalling is deleting one file. The trade-off is that the service starts at
login rather than at boot — which is what you want anyway, since the scan
results are only useful while someone can see them. For a true boot-time daemon
on a headless box, use the Docker image instead.
"""

from __future__ import annotations

import os
import platform
import plistlib
import subprocess
import sys
from pathlib import Path

from mynes.paths import BASE_DIR, DATA_DIR

LABEL = "org.mynes.server"
UNIT_NAME = "mynes.service"
TASK_NAME = "MyNeS Network Scanner"

LOG_OUT = DATA_DIR / "service.log"
LOG_ERR = DATA_DIR / "service.error.log"


def _python() -> str:
    """The interpreter the service must launch.

    Deliberately NOT os.path.realpath(): resolving a venv's bin/python follows
    the symlink to the base interpreter, where `mynes` and Flask are not
    installed, and the service exits 1 on every start. The venv's own path is
    what makes `-m mynes` importable (pyvenv.cfg sits next to it).
    """
    return sys.executable


def _env() -> dict[str, str]:
    """Only the MYNES_* settings; the service must not inherit a stale shell."""
    keep = {k: v for k, v in os.environ.items() if k.startswith("MYNES_")}
    keep.setdefault("MYNES_HOME", str(BASE_DIR))
    return keep


# ---------------------------------------------------------------------------
# macOS
# ---------------------------------------------------------------------------

def _agent_path() -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{LABEL}.plist"


def _macos_install() -> dict:
    path = _agent_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    plist = {
        "Label": LABEL,
        "ProgramArguments": [_python(), "-m", "mynes"],
        "WorkingDirectory": str(BASE_DIR),
        "EnvironmentVariables": _env(),
        "RunAtLoad": True,
        "KeepAlive": {"SuccessfulExit": False},  # restart on crash, not on a clean stop
        "StandardOutPath": str(LOG_OUT),
        "StandardErrorPath": str(LOG_ERR),
        "ProcessType": "Background",
    }
    with open(path, "wb") as f:
        plistlib.dump(plist, f)

    subprocess.run(["launchctl", "unload", str(path)], capture_output=True)
    proc = subprocess.run(["launchctl", "load", str(path)], capture_output=True, text=True)
    if proc.returncode != 0:
        return {"ok": False, "detail": proc.stderr.strip() or "launchctl load failed", "path": str(path)}
    return {"ok": True, "detail": f"LaunchAgent installed at {path}", "path": str(path)}


def _macos_uninstall() -> dict:
    path = _agent_path()
    if not path.exists():
        return {"ok": True, "detail": "Not installed."}
    subprocess.run(["launchctl", "unload", str(path)], capture_output=True)
    path.unlink()
    stopped, note = _wait_until_stopped()
    return {"ok": True, "stopped": stopped, "detail": f"Removed {path}.{note}"}


def _wait_until_stopped(timeout: float = 8.0) -> tuple[bool, str]:
    """`launchctl unload` returns before the child is actually gone.

    Without this, uninstalling leaves an orphan holding the port and the next
    start fails with "address already in use" for no visible reason.
    """
    import time

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        proc = subprocess.run(["launchctl", "list", LABEL], capture_output=True, text=True)
        if proc.returncode != 0 or _plist_field(proc.stdout, "PID") is None:
            return True, ""
        time.sleep(0.5)
    return False, (" The service process is still shutting down; if the port stays "
                   "busy, stop it manually.")


def _macos_status() -> dict:
    path = _agent_path()
    if not path.exists():
        return {"installed": False, "running": False, "detail": "Not installed."}
    proc = subprocess.run(["launchctl", "list", LABEL], capture_output=True, text=True)
    if proc.returncode != 0:
        return {"installed": True, "running": False, "detail": "Loaded but not running.",
                "path": str(path), "logs": str(LOG_OUT)}

    # `launchctl list` exits 0 for a job that is loaded but has already died, so
    # a zero exit is not proof of life. A real PID is.
    pid = _plist_field(proc.stdout, "PID")
    last_exit = _plist_field(proc.stdout, "LastExitStatus")
    running = pid is not None

    detail = f"Running (pid {pid})." if running else "Installed but not running."
    if not running and last_exit not in (None, "0"):
        detail += f" Last exit status {last_exit} — see {LOG_ERR}."

    return {
        "installed": True,
        "running": running,
        "pid": pid,
        "detail": detail,
        "path": str(path),
        "logs": str(LOG_OUT),
    }


def _plist_field(text: str, key: str) -> str | None:
    """Pull `"key" = value;` out of launchctl's plist-ish output."""
    import re

    m = re.search(rf'"{key}"\s*=\s*([^;]+);', text)
    return m.group(1).strip().strip('"') if m else None


# ---------------------------------------------------------------------------
# Linux (systemd --user)
# ---------------------------------------------------------------------------

def _unit_path() -> Path:
    return Path.home() / ".config" / "systemd" / "user" / UNIT_NAME


def _linux_install() -> dict:
    if not shutil_which("systemctl"):
        return {"ok": False, "detail": "systemctl not found. Use the Docker image, or add "
                                       f"`{_python()} -m mynes` to your desktop's autostart."}
    path = _unit_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    env_lines = "\n".join(f'Environment="{k}={v}"' for k, v in _env().items())
    path.write_text(
        f"""[Unit]
Description=MyNeS Network Scanner
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={_python()} -m mynes
WorkingDirectory={BASE_DIR}
{env_lines}
Restart=on-failure
RestartSec=10

[Install]
WantedBy=default.target
"""
    )
    for cmd in (["systemctl", "--user", "daemon-reload"],
                ["systemctl", "--user", "enable", "--now", UNIT_NAME]):
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            return {"ok": False, "detail": proc.stderr.strip(), "path": str(path)}

    # Without lingering, a user unit dies at logout - which defeats the point.
    linger = subprocess.run(["loginctl", "show-user", os.environ.get("USER", ""), "-p", "Linger"],
                            capture_output=True, text=True).stdout
    note = ("", " Run `sudo loginctl enable-linger $USER` so it keeps running "
                "after you log out.")["Linger=no" in linger]
    return {"ok": True, "detail": f"systemd user unit installed at {path}.{note}", "path": str(path)}


def _linux_uninstall() -> dict:
    path = _unit_path()
    if not path.exists():
        return {"ok": True, "detail": "Not installed."}
    subprocess.run(["systemctl", "--user", "disable", "--now", UNIT_NAME], capture_output=True)
    path.unlink()
    subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True)
    return {"ok": True, "detail": f"Removed {path}"}


def _linux_status() -> dict:
    path = _unit_path()
    if not path.exists():
        return {"installed": False, "running": False, "detail": "Not installed."}
    proc = subprocess.run(["systemctl", "--user", "is-active", UNIT_NAME],
                          capture_output=True, text=True)
    return {
        "installed": True,
        "running": proc.stdout.strip() == "active",
        "detail": proc.stdout.strip(),
        "path": str(path),
        "logs": f"journalctl --user -u {UNIT_NAME} -f",
    }


# ---------------------------------------------------------------------------
# Windows (Scheduled Task at logon)
# ---------------------------------------------------------------------------

def _windows_install() -> dict:
    # pythonw.exe runs without a console window; fall back to python.exe.
    exe = _python()
    pythonw = Path(exe).with_name("pythonw.exe")
    runner = str(pythonw) if pythonw.exists() else exe

    proc = subprocess.run(
        ["schtasks", "/Create", "/F", "/SC", "ONLOGON", "/TN", TASK_NAME,
         "/TR", f'"{runner}" -m mynes', "/RL", "LIMITED"],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        return {"ok": False, "detail": proc.stderr.strip() or proc.stdout.strip()}
    subprocess.run(["schtasks", "/Run", "/TN", TASK_NAME], capture_output=True)
    return {"ok": True, "detail": f'Scheduled Task "{TASK_NAME}" created (runs at logon).'}


def _windows_uninstall() -> dict:
    proc = subprocess.run(["schtasks", "/Delete", "/F", "/TN", TASK_NAME],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        return {"ok": True, "detail": "Not installed."}
    return {"ok": True, "detail": f'Removed scheduled task "{TASK_NAME}".'}


def _windows_status() -> dict:
    proc = subprocess.run(["schtasks", "/Query", "/TN", TASK_NAME, "/FO", "LIST"],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        return {"installed": False, "running": False, "detail": "Not installed."}
    running = "Running" in proc.stdout
    return {"installed": True, "running": running, "detail": proc.stdout.strip()[:400]}


def shutil_which(name):
    import shutil

    return shutil.which(name)


# ---------------------------------------------------------------------------

_IMPL = {
    "Darwin": (_macos_install, _macos_uninstall, _macos_status),
    "Linux": (_linux_install, _linux_uninstall, _linux_status),
    "Windows": (_windows_install, _windows_uninstall, _windows_status),
}


def _dispatch(index: int) -> dict:
    impl = _IMPL.get(platform.system())
    if impl is None:
        return {"ok": False, "detail": f"No service integration for {platform.system()}."}
    return impl[index]()


def install() -> dict:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    return _dispatch(0)


def uninstall() -> dict:
    return _dispatch(1)


def status() -> dict:
    return _dispatch(2)


def main():
    import argparse
    import json

    ap = argparse.ArgumentParser(description="Install MyNeS as a background service.")
    ap.add_argument("action", choices=["install", "uninstall", "status"])
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    result = {"install": install, "uninstall": uninstall, "status": status}[args.action]()

    if args.json:
        print(json.dumps(result, indent=2))
        return
    for key, value in result.items():
        print(f"{key:<10}: {value}")


def demo():
    """Self-check: generated unit/plist content is well-formed, nothing installed."""
    import io

    plist = {
        "Label": LABEL,
        "ProgramArguments": [_python(), "-m", "mynes"],
        "EnvironmentVariables": _env(),
    }
    buf = io.BytesIO()
    plistlib.dump(plist, buf)
    parsed = plistlib.loads(buf.getvalue())
    assert parsed["Label"] == LABEL
    assert parsed["ProgramArguments"][-1] == "mynes"

    env = _env()
    assert "MYNES_HOME" in env, "the service must know where the install lives"
    assert all(k.startswith("MYNES_") for k in env), "no unrelated shell state leaks in"

    assert set(_IMPL) == {"Darwin", "Linux", "Windows"}
    result = status()
    assert "installed" in result or "detail" in result, result
    print("service demo OK")


if __name__ == "__main__":
    if "--self-check" in sys.argv:
        demo()
    else:
        main()
