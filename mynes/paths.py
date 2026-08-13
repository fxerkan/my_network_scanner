"""Filesystem locations, resolved from the package (not the CWD).

Every path is overridable by env var so Docker / packaged installs can point at
a mounted volume without touching code.
"""

import os
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent

# `.env` is loaded by mynes/__init__.py, which always runs before this module,
# so os.environ is already populated by the time we read it here.
BASE_DIR = Path(os.environ.get("MYNES_HOME") or PACKAGE_DIR.parent)

CONFIG_DIR = Path(os.environ.get("MYNES_CONFIG_DIR") or BASE_DIR / "config")
DATA_DIR = Path(os.environ.get("MYNES_DATA_DIR") or BASE_DIR / "data")

WEB_DIR = PACKAGE_DIR / "web"
TEMPLATES_DIR = WEB_DIR / "templates"
STATIC_DIR = WEB_DIR / "static"
LOCALES_DIR = WEB_DIR / "locales"

for _d in (CONFIG_DIR, DATA_DIR):
    _d.mkdir(parents=True, exist_ok=True)


def seed_config_defaults():
    """Copy any *missing* static config file from the image's baked defaults
    into the (possibly bind-mounted) config dir.

    A container bind-mounts config/, so files added to the app after the host's
    config dir was first created never arrive - that is why emojis.csv was
    missing (empty emoji picker) and device_types.json went stale on rpifx.
    Copy-if-missing only: user edits and existing data are never touched, and
    nothing is ever deleted, so a container update cannot wipe anything.
    Dotfiles are skipped so per-install secrets (.master_password, .salt, …)
    are never seeded from the image. No-op when MYNES_CONFIG_DEFAULTS is unset
    (every non-container install already has its own populated config/).
    """
    import shutil

    src = os.environ.get("MYNES_CONFIG_DEFAULTS")
    if not src or not os.path.isdir(src) or os.path.realpath(src) == os.path.realpath(CONFIG_DIR):
        return
    for name in os.listdir(src):
        if name.startswith("."):
            continue
        s, d = os.path.join(src, name), CONFIG_DIR / name
        if os.path.isfile(s) and not d.exists():
            try:
                shutil.copy2(s, d)
            except OSError as e:
                print(f"config seed skipped {name}: {e}")


seed_config_defaults()


def config_file(name: str) -> str:
    return str(CONFIG_DIR / name)


def data_file(name: str) -> str:
    return str(DATA_DIR / name)


def load_local(name: str) -> dict:
    """Read a settings file from the data dir. Missing or corrupt -> {}.

    config/config.json is tracked in git, so anything per-install - notification
    channels with tokens, whether sign-in is required - belongs here instead.
    """
    import json

    path = data_file(name)
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh) or {}
    except (OSError, ValueError):
        return {}


def save_local(name: str, data: dict) -> dict:
    """Write it back, owner-readable only - these files can hold secrets."""
    import json

    path = data_file(name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
    os.chmod(path, 0o600)
    return data
