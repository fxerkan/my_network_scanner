"""MyNeS - My Network Scanner.

`.env` is loaded here, at package import, so every entry point gets it: the web
app, `python -m mynes`, the tray icon, and one-off scripts alike. Doing it in a
submodule only worked for the modules that happened to import that submodule.
"""

import os
from pathlib import Path

__all__ = ["load_dotenv", "DOTENV_KEYS"]


def load_dotenv(path: Path | None = None) -> list[str]:
    """Read `.env` from the project root into os.environ.

    Real environment variables always win, so `MYNES_PORT=5899 python -m mynes`
    still overrides the file. Returns the names it set - never the values, which
    are secrets and must not reach a log.

    ponytail: ~20 lines of stdlib instead of python-dotenv. Handles `KEY=value`,
    `export KEY=value`, quoted values and `#` comments, which is the whole of the
    format anyone uses here.
    """
    env_path = path or Path(__file__).resolve().parent.parent / ".env"
    if not env_path.is_file():
        return []

    applied = []
    for raw in env_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.removeprefix("export ").partition("=")
        key, value = key.strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key and key not in os.environ:
            os.environ[key] = value
            applied.append(key)
    return applied


DOTENV_KEYS = load_dotenv()
