#!/usr/bin/env python3
"""Stamp the current version into the marketplace manifests and deploy files.

pyproject.toml is the single source of truth. App stores (CasaOS, Umbrel, HA,
runtipi, ...) drive their "update available" prompt off a concrete version, so
the image is pinned to that version rather than `latest`, and the manifest
version field is kept equal to it. This runs from `release_bump.py --apply`;
`--check` makes CI fail if any target drifted from pyproject.

    python scripts/sync_version.py           # rewrite the targets in place
    python scripts/sync_version.py --check    # exit 1 if any are stale (CI)
"""
from __future__ import annotations

import argparse
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SEMVER = r"\d+\.\d+\.\d+"

# Each pattern keeps group 1 (the prefix) and rewrites the version after it.
IMAGE = re.compile(r"(fxerkan/my_network_scanner:)" + SEMVER)
# The key must be exactly `version` — the lookbehind rejects e.g. min_tipi_version.
VERSION_FIELD = re.compile(r'(?<![\w])(version"?\s*[:=]\s*")' + SEMVER)
RELEASE_URL = re.compile(r"(releases/tag/v)" + SEMVER)

# path -> which patterns apply. Docs get the image tag only; their version-history
# prose is deliberately left alone (rewriting it would falsify past releases).
TARGETS: dict[str, list[re.Pattern]] = {
    "deploy/marketplaces/casaos/docker-compose.yml": [IMAGE, VERSION_FIELD],
    "deploy/marketplaces/portainer/docker-compose.yml": [IMAGE],
    "deploy/marketplaces/umbrel/docker-compose.yml": [IMAGE],
    "deploy/marketplaces/umbrel/umbrel-app.yml": [VERSION_FIELD, RELEASE_URL],
    "deploy/marketplaces/runtipi/docker-compose.yml": [IMAGE],
    "deploy/marketplaces/runtipi/config.json": [VERSION_FIELD],
    "deploy/marketplaces/coolify/mynes.yaml": [IMAGE],
    "deploy/marketplaces/cosmos/cosmos-compose.json": [IMAGE],
    "deploy/marketplaces/homeassistant-addon/mynes/config.yaml": [VERSION_FIELD],
}


def current_version() -> str:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.M)
    if not match:
        sys.exit("no version found in pyproject.toml")
    return match.group(1)


def rewrite(text: str, patterns: list[re.Pattern], version: str) -> str:
    for pattern in patterns:
        text = pattern.sub(lambda m: m.group(1) + version, text)
    return text


def sync(version: str, check: bool) -> int:
    stale: list[str] = []
    for rel, patterns in TARGETS.items():
        file = ROOT / rel
        if not file.exists():
            print(f"missing: {rel}", file=sys.stderr)
            stale.append(rel)
            continue
        text = file.read_text(encoding="utf-8")
        new = rewrite(text, patterns, version)
        if new == text:
            continue
        if check:
            stale.append(rel)
        else:
            file.write_text(new, encoding="utf-8")
            print(f"synced {rel} -> {version}")
    if check and stale:
        print(f"\nout of sync with pyproject ({version}): " + ", ".join(stale), file=sys.stderr)
        print("run: python scripts/sync_version.py", file=sys.stderr)
        return 1
    if not check and not stale:
        print(f"all targets at {version}")
    return 0


def demo() -> None:
    """Self-check the regexes: rewrite what should change, spare what must not."""
    assert rewrite("image: fxerkan/my_network_scanner:1.4.0\n", [IMAGE], "1.4.2") \
        == "image: fxerkan/my_network_scanner:1.4.2\n"
    # :latest must be left alone (it is not a 3-part semver).
    assert rewrite("image: fxerkan/my_network_scanner:latest\n", [IMAGE], "1.4.2") \
        == "image: fxerkan/my_network_scanner:latest\n"
    assert rewrite('version: "1.4.0"', [VERSION_FIELD], "1.4.2") == 'version: "1.4.2"'
    assert rewrite('"version": "1.4.0",', [VERSION_FIELD], "1.4.2") == '"version": "1.4.2",'
    # A different key that merely ends in "version" must not be touched.
    assert rewrite('"min_tipi_version": "4.5.0"', [VERSION_FIELD], "1.4.2") \
        == '"min_tipi_version": "4.5.0"'
    # A compose schema version ("3.8") is 2-part, so it never matches.
    assert rewrite('version: "3.8"', [VERSION_FIELD], "1.4.2") == 'version: "3.8"'
    assert rewrite("releases/tag/v1.4.0", [RELEASE_URL], "1.4.2") == "releases/tag/v1.4.2"
    print("sync_version demo OK")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true",
                        help="exit 1 if any target is out of sync (no writes)")
    parser.add_argument("--demo", action="store_true", help="run the self-check")
    args = parser.parse_args()
    if args.demo:
        demo()
        return 0
    return sync(current_version(), args.check)


if __name__ == "__main__":
    sys.exit(main())
