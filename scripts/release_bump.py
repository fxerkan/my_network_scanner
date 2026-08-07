#!/usr/bin/env python3
"""Decide the next version from the commits since the last tag.

SemVer, but scope-driven: PATCH is the floor, MINOR/MAJOR must be earned.

    MAJOR  a breaking, root change the user has to react to. Auto-detected from
           "feat!:", "fix!:", or a "BREAKING CHANGE:" trailer (never silent),
           or forced with --major. Rare.
    MINOR  a substantial new capability or subsystem. NEVER automatic: you opt
           in with --minor when the scope actually warrants a milestone.
    PATCH  the default for everything else that ships - fixes, small features,
           improvements, refactors. This is what accumulates: 1.4.1 -> 1.4.12.

A single "feat:" no longer forces a minor bump. Graph zoom is a patch; a whole
new discovery protocol is a --minor. You (or the agent) make that call - see
the "Versioning" rubric in CLAUDE.md.

Changes that never reach a user's install do not earn a release at all.
`docs/`, `deploy/`, `tests/`, `.github/` and the top-level markdown are all
outside the package: a typo fix in the README is not a new version.

    python scripts/release_bump.py            # what would the next version be
    python scripts/release_bump.py --minor    # cut a milestone instead of a patch
    python scripts/release_bump.py --apply    # write it into pyproject + version.py
"""
from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Everything outside these prefixes is support material, not the shipped app.
RELEASABLE = ("mynes/", "config/", "scripts/", "pyproject.toml")


def run(*args: str) -> str:
    return subprocess.run(args, cwd=ROOT, capture_output=True, text=True).stdout.strip()


def last_tag() -> str | None:
    tag = run("git", "describe", "--tags", "--abbrev=0")
    return tag or None


def changed_files(since: str | None) -> list[str]:
    rng = f"{since}..HEAD" if since else "HEAD"
    return [f for f in run("git", "diff", "--name-only", rng).splitlines() if f]


def commit_subjects(since: str | None) -> list[str]:
    rng = f"{since}..HEAD" if since else "HEAD"
    return [c for c in run("git", "log", "--format=%B%x00", rng).split("\0") if c.strip()]


def bump_for(commits: list[str], override: str | None = None) -> str:
    """Default is patch. Breaking commits force major (never silent). Minor is
    opt-in only, via --minor: a plain "feat:" is a patch, not a milestone."""
    if override in ("major", "minor", "patch"):
        return override
    for message in commits:
        subject = message.strip().splitlines()[0] if message.strip() else ""
        if "BREAKING CHANGE:" in message or re.match(r"^\w+(\([^)]*\))?!:", subject):
            return "major"
    return "patch"


def next_version(current: str, level: str) -> str:
    major, minor, patch = (int(p) for p in current.split(".")[:3])
    if level == "major":
        return f"{major + 1}.0.0"
    if level == "minor":
        return f"{major}.{minor + 1}.0"
    return f"{major}.{minor}.{patch + 1}"


def current_version() -> str:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.M)
    if not match:
        sys.exit("no version found in pyproject.toml")
    return match.group(1)


def apply(version: str) -> None:
    for path, pattern, replacement in (
        ("pyproject.toml", r'^version\s*=\s*"[^"]+"', f'version = "{version}"'),
        ("mynes/core/version.py", r'^VERSION\s*=\s*"[^"]+"', f'VERSION = "{version}"'),
    ):
        file = ROOT / path
        file.write_text(re.sub(pattern, replacement, file.read_text(encoding="utf-8"), count=1, flags=re.M),
                        encoding="utf-8")
        print(f"updated {path}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--apply", action="store_true", help="write the new version to disk")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--minor", dest="override", action="store_const", const="minor",
                       help="cut a milestone: a substantial new capability")
    group.add_argument("--major", dest="override", action="store_const", const="major",
                       help="force a breaking release (usually auto-detected)")
    group.add_argument("--patch", dest="override", action="store_const", const="patch",
                       help="force a patch even over a breaking marker")
    args = parser.parse_args()

    since = last_tag()
    files = changed_files(since)
    if not files:
        print(f"nothing changed since {since or 'the first commit'}")
        return 0

    shipped = [f for f in files if f.startswith(RELEASABLE)]
    print(f"since {since or 'the first commit'}: {len(files)} files changed, "
          f"{len(shipped)} of them shipped")
    if not shipped:
        print("docs / deploy / tests only — no release.")
        return 0

    level = bump_for(commit_subjects(since), args.override)
    version = next_version(current_version(), level)
    print(f"{current_version()} -> {version}  ({level})")
    if args.apply:
        apply(version)
        print(f"\nnext: git commit -am 'release: v{version}' && git tag v{version}")
    return 0


def demo():
    """Self-check for the two decisions this script actually makes."""
    assert bump_for(["fix: typo"]) == "patch"
    # A plain feat: is a patch now - minor is opt-in, not commit-triggered.
    assert bump_for(["fix: typo", "feat: graph zoom"]) == "patch"
    assert bump_for(["feat!: drop python 3.9"]) == "major"
    assert bump_for(["feat: x\n\nBREAKING CHANGE: config moved"]) == "major"
    assert bump_for(["docs: readme"]) == "patch"
    # Explicit overrides win; --patch even overrides a breaking marker.
    assert bump_for(["fix: typo"], "minor") == "minor"
    assert bump_for(["feat!: break"], "patch") == "patch"
    assert next_version("1.4.0", "minor") == "1.5.0"
    assert next_version("1.4.3", "patch") == "1.4.4"
    assert next_version("1.4.3", "major") == "2.0.0"
    # Support directories must not be mistaken for shipped code.
    assert not any(f.startswith(RELEASABLE) for f in ["docs/a.md", "tests/t.py", "deploy/x.yml", "README.md"])
    assert all(f.startswith(RELEASABLE) for f in ["mynes/web/app.py", "config/config.json"])
    print("release_bump demo OK")


if __name__ == "__main__":
    if "--demo" in sys.argv:
        demo()
    else:
        sys.exit(main())
