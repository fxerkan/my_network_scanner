"""Raw-socket privileges, per platform, without asking users to run as root.

Layer-2 ARP scanning needs raw packet access. The lazy answer is "run with
sudo", but that means the whole web app runs as root forever — a bad trade for
a service that parses network input. Every platform has a narrower, permanent
way to grant just this one capability:

- **Linux**: `setcap cap_net_raw,cap_net_admin+eip` on the Python binary.
  The interpreter gains exactly two capabilities; nothing runs as root.
- **macOS**: the BPF devices (`/dev/bpf*`) are root-only at 0600. Wireshark
  solves this with an `access_bpf` group plus a boot-time LaunchDaemon that
  re-applies the group each restart. We install the same thing.
- **Windows**: packet capture goes through Npcap. Installing it with
  "WinPcap API-compatible mode" lets a normal user capture; without Npcap no
  amount of elevation helps scapy.

Nothing here runs privileged commands behind the user's back. `plan()` returns
the exact commands; `apply()` runs them only when explicitly asked, so the OS
password prompt appears in the user's own terminal.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass, field

from mynes.core.arp import has_raw_socket_privilege

CHMOD_BPF_LABEL = "org.mynes.ChmodBPF"
CHMOD_BPF_PLIST = f"/Library/LaunchDaemons/{CHMOD_BPF_LABEL}.plist"
CHMOD_BPF_SCRIPT = "/Library/Application Support/MyNeS/ChmodBPF"


@dataclass
class Plan:
    """What to do about privileges on this machine."""

    platform: str
    already_ok: bool
    summary: str
    commands: list[str] = field(default_factory=list)
    needs_sudo: bool = True
    needs_logout: bool = False
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "platform": self.platform,
            "already_ok": self.already_ok,
            "summary": self.summary,
            "commands": self.commands,
            "needs_sudo": self.needs_sudo,
            "needs_logout": self.needs_logout,
            "notes": self.notes,
        }


def _real_python() -> str:
    """The actual interpreter binary, not the venv symlink.

    setcap must be applied to the real file: capabilities do not follow symlinks,
    and a venv's bin/python is almost always a symlink into the base install.
    """
    return os.path.realpath(sys.executable)


def _linux_plan() -> Plan:
    binary = _real_python()
    notes = []

    if not shutil.which("setcap"):
        notes.append(
            "`setcap` is missing. Install libcap: "
            "`sudo apt install libcap2-bin` (Debian/Ubuntu) or "
            "`sudo dnf install libcap` (Fedora/RHEL)."
        )

    # A capability-bearing interpreter ignores LD_LIBRARY_PATH, so a Python
    # built against libraries outside the default loader path stops working.
    if not binary.startswith(("/usr/", "/bin", "/opt/")):
        notes.append(
            f"{binary} lives outside the system paths. If Python fails to start "
            "after setcap, its shared libraries are not on the default loader "
            "path — add them to /etc/ld.so.conf.d/ and run ldconfig, or use the "
            "Docker image instead."
        )

    notes.append(
        "This grants CAP_NET_RAW to the interpreter itself, so ANY script run "
        "with it can craft raw packets. Prefer a dedicated venv for MyNeS."
    )

    return Plan(
        platform="linux",
        already_ok=False,
        summary="Grant CAP_NET_RAW + CAP_NET_ADMIN to the Python interpreter",
        commands=[f"sudo setcap cap_net_raw,cap_net_admin+eip {binary}"],
        needs_sudo=True,
        notes=notes,
    )


def _macos_plan() -> Plan:
    """Install an access_bpf group plus a boot-time daemon, as Wireshark does."""
    user = os.environ.get("USER") or os.environ.get("LOGNAME") or "$USER"
    script_dir = os.path.dirname(CHMOD_BPF_SCRIPT)

    commands = [
        f"sudo mkdir -p '{script_dir}'",
        f"sudo cp '{_bundled_chmod_bpf_path()}' '{CHMOD_BPF_SCRIPT}'",
        f"sudo chmod 755 '{CHMOD_BPF_SCRIPT}'",
        f"sudo cp '{_bundled_plist_path()}' '{CHMOD_BPF_PLIST}'",
        f"sudo chown root:wheel '{CHMOD_BPF_PLIST}'",
        f"sudo chmod 644 '{CHMOD_BPF_PLIST}'",
        f"sudo launchctl load '{CHMOD_BPF_PLIST}'",
        f"sudo dseditgroup -o edit -a {user} -t user access_bpf",
    ]
    return Plan(
        platform="macos",
        already_ok=False,
        summary="Install the ChmodBPF daemon and join the access_bpf group",
        commands=commands,
        needs_sudo=True,
        needs_logout=True,
        notes=[
            "The daemon re-applies BPF permissions at every boot, so this "
            "survives restarts (macOS resets /dev/bpf* to root-only).",
            "Group membership only takes effect in a NEW login session — log "
            "out and back in, or reboot, after running this.",
            "This is the same mechanism Wireshark installs. If you already have "
            "Wireshark's ChmodBPF, you only need the dseditgroup line.",
        ],
    )


def _windows_plan() -> Plan:
    npcap = os.path.exists(r"C:\Windows\System32\Npcap") or os.path.exists(
        r"C:\Program Files\Npcap"
    )
    commands = []
    notes = []
    if not npcap:
        commands.append("winget install --id Insecure.Npcap -e")
        notes.append(
            "During the Npcap installer, tick 'Install Npcap in WinPcap "
            "API-compatible Mode' and 'Restrict Npcap driver's access to "
            "Administrators only' — UNTICK the latter so MyNeS can capture "
            "without running elevated."
        )
    else:
        notes.append(
            "Npcap is installed. If scanning still finds nothing, Npcap was "
            "likely installed with 'Administrators only' access — re-run its "
            "installer and untick that option, or start MyNeS elevated."
        )
    notes.append("Without Npcap, scapy cannot send raw packets on Windows at all.")

    return Plan(
        platform="windows",
        already_ok=False,
        summary="Install Npcap (packet capture driver) with unrestricted access",
        commands=commands,
        needs_sudo=bool(commands),
        notes=notes,
    )


def _bundled_chmod_bpf_path() -> str:
    from mynes.paths import PACKAGE_DIR

    return str(PACKAGE_DIR / "platform" / "files" / "ChmodBPF")


def _bundled_plist_path() -> str:
    from mynes.paths import PACKAGE_DIR

    return str(PACKAGE_DIR / "platform" / "files" / f"{CHMOD_BPF_LABEL}.plist")


def plan() -> Plan:
    """Work out what, if anything, this machine needs."""
    if has_raw_socket_privilege():
        return Plan(
            platform=platform.system().lower(),
            already_ok=True,
            summary="Raw socket access is already available — full ARP scanning is active.",
            needs_sudo=False,
        )

    system = platform.system()
    if system == "Linux":
        return _linux_plan()
    if system == "Darwin":
        return _macos_plan()
    if system == "Windows":
        return _windows_plan()
    return Plan(
        platform=system.lower(),
        already_ok=False,
        summary=f"No automated privilege setup for {system}. Run MyNeS as root for full scanning.",
        commands=[],
        needs_sudo=True,
    )


def apply(p: Plan | None = None, dry_run: bool = False) -> dict:
    """Run the plan's commands. Only ever called from an explicit --apply."""
    p = p or plan()
    if p.already_ok:
        return {"ok": True, "changed": False, "detail": p.summary}
    if not p.commands:
        return {"ok": False, "changed": False, "detail": p.summary, "notes": p.notes}

    results = []
    for cmd in p.commands:
        if dry_run:
            results.append({"command": cmd, "skipped": True})
            continue
        proc = subprocess.run(cmd, shell=True)  # noqa: S602 - fixed, non-user-supplied commands
        results.append({"command": cmd, "returncode": proc.returncode})
        if proc.returncode != 0:
            return {"ok": False, "changed": True, "results": results,
                    "detail": f"Command failed: {cmd}"}

    return {
        "ok": True,
        "changed": not dry_run,
        "results": results,
        "detail": "Done." + (" Log out and back in for it to take effect." if p.needs_logout else ""),
        "notes": p.notes,
    }


def main():
    import argparse

    ap = argparse.ArgumentParser(description="Check or fix raw-scanning privileges for MyNeS.")
    ap.add_argument("--apply", action="store_true",
                    help="run the commands (you will be prompted for your password)")
    ap.add_argument("--dry-run", action="store_true", help="print what --apply would run")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()

    p = plan()

    if args.json:
        import json
        print(json.dumps(p.to_dict(), indent=2))
        return

    print(f"Platform        : {p.platform}")
    print(f"Raw scanning    : {'available' if p.already_ok else 'NOT available'}")
    print(f"                  {p.summary}\n")

    if p.already_ok:
        return

    if p.commands:
        print("Run these to fix it permanently:\n")
        for cmd in p.commands:
            print(f"    {cmd}")
        print()

    for note in p.notes:
        print(f"  ! {note}")
    if p.notes:
        print()

    if args.apply or args.dry_run:
        result = apply(p, dry_run=args.dry_run)
        print(result["detail"])
    elif p.commands:
        print("Re-run with --apply to execute them, or copy them yourself.")
        print("Either way MyNeS keeps working: it falls back to a ping sweep,")
        print("which finds most devices but misses ones that ignore ICMP.")


def demo():
    """Self-check: a plan is always coherent and never silently empty."""
    p = plan()
    assert p.platform, "platform must be identified"
    assert p.summary, "every plan needs a human-readable summary"
    if p.already_ok:
        assert not p.commands, "nothing to do when privileges already exist"
        assert not p.needs_sudo
    else:
        # An actionable plan must either give commands or explain why it cannot.
        assert p.commands or p.notes or "No automated" in p.summary, p

    # apply() must be a no-op unless explicitly told to run.
    result = apply(p, dry_run=True)
    assert result["changed"] is False, "dry run must not change anything"

    for builder in (_linux_plan, _macos_plan, _windows_plan):
        q = builder()
        assert q.summary and q.notes, builder.__name__
        assert all(c.strip() for c in q.commands), builder.__name__
    print("privileges demo OK")


if __name__ == "__main__":
    if "--self-check" in sys.argv:
        demo()
    else:
        main()
