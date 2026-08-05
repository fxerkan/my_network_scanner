#!/usr/bin/env python3
"""Decide the next version from the commits since the last tag.

SemVer, the way GitHub recommends it:

    MAJOR  a breaking change - config or API shape the user has to react to
           ("feat!:", "fix!:", or a "BREAKING CHANGE:" trailer)
    MINOR  a new capability                                    ("feat:")
    PATCH  anything else that ships                            ("fix:", "perf:", ...)

Changes that never reach a user's install do not earn a release at all.
`docs/`, `deploy/`, `tests/`, `.github/` and the top-level markdown are all
outside the package: a typo fix in the README is not version 1.4.1.

    python scripts/release_bump.py            # what would the next version be
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


def bump_for(commits: list[str]) -> str:
    """The largest bump any single commit asks for."""
    level = "patch"
    for message in commits:
        subject = message.strip().splitlines()[0] if message.strip() else ""
        if "BREAKING CHANGE:" in message or re.match(r"^\w+(\([^)]*\))?!:", subject):
            return "major"
        if subject.startswith("feat"):
            level = "minor"
    return level


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

    level = bump_for(commit_subjects(since))
    version = next_version(current_version(), level)
    print(f"{current_version()} -> {version}  ({level})")
    if args.apply:
        apply(version)
        print(f"\nnext: git commit -am 'release: v{version}' && git tag v{version}")
    return 0


def demo():
    """Self-check for the two decisions this script actually makes."""
    assert bump_for(["fix: typo"]) == "patch"
    assert bump_for(["fix: typo", "feat: graph zoom"]) == "minor"
    assert bump_for(["feat!: drop python 3.9"]) == "major"
    assert bump_for(["feat: x\n\nBREAKING CHANGE: config moved"]) == "major"
    assert bump_for(["docs: readme"]) == "patch"
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
