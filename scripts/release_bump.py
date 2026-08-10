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
import datetime
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


def _auto_notes(since: str | None) -> str:
    """Fallback release notes built from commit subjects since the last tag, so a
    version section is NEVER shipped empty when nobody wrote '## [Unreleased]'
    entries during development. Release/chore/merge noise is dropped."""
    seen, lines = set(), []
    for message in commit_subjects(since):
        subject = message.strip().splitlines()[0] if message.strip() else ""
        low = subject.lower()
        if not subject or low.startswith(("release:", "chore:", "bump", "merge ")):
            continue
        if subject in seen:
            continue
        seen.add(subject)
        lines.append(f"- {subject}")
    return "\n".join(lines)


def promote_unreleased(text: str, heading: str, auto: str) -> tuple[str, bool]:
    """Pure: move the '## [Unreleased]' body under a new dated `heading`, leaving
    a fresh empty Unreleased. When that body is blank, fall back to `auto` so the
    section is never empty. Returns (new_text, auto_filled)."""
    if "## [Unreleased]" not in text:
        return text, False
    head, _, rest = text.partition("## [Unreleased]")
    carried, sep, tail = rest.partition("\n## ")
    carried = carried.strip()
    auto_filled = not carried
    if auto_filled:
        carried = auto.strip()
    if sep:
        return f"{head}## [Unreleased]\n\n{heading}\n\n{carried}\n\n## {tail}", auto_filled
    return f"{head}## [Unreleased]\n\n{heading}\n\n{carried}\n", auto_filled


def stamp_changelog(version: str, today: str, since: str | None = None) -> str:
    """Promote the '## [Unreleased]' block to a dated version section. If it has no
    hand-written entries, auto-fill from the commits since `since` so a blank
    section is never shipped (the old code did). Returns the notes body for the
    GitHub release."""
    path = ROOT / "CHANGELOG.md"
    text = path.read_text(encoding="utf-8")
    heading = f"## [{version}] — {today}"

    if f"## [{version}]" in text:
        print(f"CHANGELOG.md already has a [{version}] section — left as-is")
    elif "## [Unreleased]" in text:
        text, auto_filled = promote_unreleased(text, heading, _auto_notes(since))
        path.write_text(text, encoding="utf-8")
        if auto_filled:
            print("no [Unreleased] entries — auto-filled the section from commits")
        print("updated CHANGELOG.md")
    else:
        print("CHANGELOG.md has no [Unreleased] section — skipped")

    body = re.split(rf"^{re.escape(heading)}\s*$", text, maxsplit=1, flags=re.M)
    notes = body[1].split("\n## ", 1)[0].strip() if len(body) > 1 else ""
    if "assets/screenshots/" not in notes and "![" not in notes:
        print("⚠️  reminder: add screenshot(s) of the changes to this section "
              "(![...](assets/screenshots/<name>.png)) before publishing.")
    return notes


def apply(version: str) -> None:
    for path, pattern, replacement in (
        ("pyproject.toml", r'^version\s*=\s*"[^"]+"', f'version = "{version}"'),
        ("mynes/core/version.py", r'^VERSION\s*=\s*"[^"]+"', f'VERSION = "{version}"'),
    ):
        file = ROOT / path
        file.write_text(re.sub(pattern, replacement, file.read_text(encoding="utf-8"), count=1, flags=re.M),
                        encoding="utf-8")
        print(f"updated {path}")
    stamp_changelog(version, datetime.date.today().isoformat(), since=last_tag())
    # Propagate the version into the marketplace manifests and deploy files.
    subprocess.run([sys.executable, str(ROOT / "scripts" / "sync_version.py")], cwd=ROOT, check=True)


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
        print(f"\nnext: git commit -am 'release: v{version}' && git tag v{version} && "
              f"git push origin HEAD --tags")
        print("(pushing the tag builds+publishes the image and cuts the GitHub release)")
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
    # Changelog stamp: [Unreleased] body is carried into the dated heading.
    sample = "## [Unreleased]\n\n### Added\n- a thing\n\n## [1.0.0] — 2020-01-01\n"
    promoted, auto = promote_unreleased(sample, "## [1.1.0] — 2020-02-02", "- from commits")
    assert not auto
    assert promoted.count("## [Unreleased]") == 1
    notes = re.split(r"^## \[1\.1\.0\] — 2020-02-02\s*$", promoted, maxsplit=1, flags=re.M)[1].split("\n## ", 1)[0].strip()
    assert notes == "### Added\n- a thing", notes
    # Empty [Unreleased] must be auto-filled, never shipped blank (the old bug).
    blank = "## [Unreleased]\n\n## [1.0.0] — 2020-01-01\n"
    promoted2, auto2 = promote_unreleased(blank, "## [1.1.0] — 2020-02-02", "- from commits")
    assert auto2
    notes2 = re.split(r"^## \[1\.1\.0\] — 2020-02-02\s*$", promoted2, maxsplit=1, flags=re.M)[1].split("\n## ", 1)[0].strip()
    assert notes2 == "- from commits", notes2
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
