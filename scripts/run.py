#!/usr/bin/env python3
"""Cross-platform launcher: creates a venv, installs deps, starts MyNeS.

    python scripts/run.py            # setup (if needed) + start
    python scripts/run.py --setup    # setup only
    python scripts/run.py --extras all

Works the same on Windows, macOS and Linux; only the stdlib is used here so it
runs before anything is installed.
"""

import argparse
import os
import shutil
import subprocess
import sys
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VENV = ROOT / ".venv"
PY = VENV / ("Scripts/python.exe" if os.name == "nt" else "bin/python")

NMAP_HINT = {
    "win32": "winget install Insecure.Nmap   (or https://nmap.org/download.html)",
    "darwin": "brew install nmap",
}.get(sys.platform, "sudo apt-get install nmap   # or your distro's package manager")


def run(*cmd):
    subprocess.check_call(cmd)


def ensure_venv(extras: str):
    if not PY.exists():
        print(f"Creating virtualenv at {VENV}")
        venv.EnvBuilder(with_pip=True).create(VENV)
    print(f"Installing MyNeS[{extras}]")
    run(str(PY), "-m", "pip", "install", "--quiet", "--upgrade", "pip")
    run(str(PY), "-m", "pip", "install", "--quiet", "-e", f"{ROOT}[{extras}]")


def check_nmap():
    if shutil.which("nmap"):
        return
    print(f"\n!  nmap not found - port scanning will be skipped.\n   Install it with: {NMAP_HINT}\n")


def main():
    ap = argparse.ArgumentParser(description="Set up and run MyNeS")
    ap.add_argument("--setup", action="store_true", help="install dependencies and exit")
    ap.add_argument("--extras", default="discovery", help="pip extras: discovery, bluetooth, analysis, all")
    ap.add_argument("--port", default=os.environ.get("MYNES_PORT", "5883"))
    args = ap.parse_args()

    ensure_venv(args.extras)
    check_nmap()
    if args.setup:
        print("Setup complete. Start with: python scripts/run.py")
        return

    print(f"MyNeS starting -> http://localhost:{args.port}   (Ctrl+C to stop)")
    env = {**os.environ, "MYNES_PORT": str(args.port)}
    # ponytail: exec-style handoff so Ctrl+C goes straight to the server.
    sys.exit(subprocess.call([str(PY), "-m", "mynes"], cwd=ROOT, env=env))


if __name__ == "__main__":
    main()
