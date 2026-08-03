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


def config_file(name: str) -> str:
    return str(CONFIG_DIR / name)


def data_file(name: str) -> str:
    return str(DATA_DIR / name)
