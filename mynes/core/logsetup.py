"""Application logging: one rotating file plus an in-memory ring buffer.

Before this, everything was bare print()/getLogger() to stderr with no file and
no way for the UI to show logs. This wires the root logger to a rotating file in
DATA_DIR and keeps the last N records in memory so the Settings > Logs tab can
read them back without parsing the file on every request.

ponytail: a deque ring buffer is enough for one box; if logs ever need full-text
search across history, point the Logs API at the rotated files on disk instead.
"""

from __future__ import annotations

import logging
import logging.handlers
from collections import deque
from pathlib import Path

from mynes.paths import DATA_DIR

LOG_FILE = str(Path(DATA_DIR) / "mynes.log")
_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"
_DATEFMT = "%Y-%m-%d %H:%M:%S"

# Level names the UI offers, coarse-to-fine.
LEVELS = ["ERROR", "WARNING", "INFO", "DEBUG"]

_configured = False


class _RingHandler(logging.Handler):
    """Keep the most recent records in memory for the Logs API to read cheaply."""

    def __init__(self, capacity: int = 2000):
        super().__init__()
        self.buffer: deque = deque(maxlen=capacity)

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.buffer.append({
                "time": self.formatter.formatTime(record, _DATEFMT) if self.formatter else "",
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
            })
        except Exception:  # noqa: BLE001 - logging must never raise into callers
            pass


_ring = _RingHandler()


def setup_logging(level: str = "INFO") -> None:
    """Attach a rotating file handler + the ring buffer to the root logger once."""
    global _configured
    root = logging.getLogger()
    fmt = logging.Formatter(_FORMAT, _DATEFMT)
    _ring.setFormatter(fmt)

    if not _configured:
        Path(DATA_DIR).mkdir(parents=True, exist_ok=True)
        fileh = logging.handlers.RotatingFileHandler(
            LOG_FILE, maxBytes=2 * 1024 * 1024, backupCount=3, encoding="utf-8")
        fileh.setFormatter(fmt)
        root.addHandler(fileh)
        root.addHandler(_ring)
        # Scapy stays quiet regardless of the app level.
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
        _configured = True

    set_level(level)


def set_level(level: str) -> str:
    """Set the root log level. Returns the normalised level name."""
    level = (level or "INFO").upper()
    if level not in LEVELS:
        level = "INFO"
    logging.getLogger().setLevel(getattr(logging, level))
    return level


def get_level() -> str:
    return logging.getLevelName(logging.getLogger().level)


def recent(limit: int = 500, level: str | None = None, query: str | None = None) -> list:
    """Most-recent-last records, optionally filtered by minimum level and text."""
    records = list(_ring.buffer)
    if level and level.upper() in LEVELS:
        floor = LEVELS.index(level.upper())
        allowed = set(LEVELS[: floor + 1])
        records = [r for r in records if r["level"] in allowed]
    if query:
        q = query.lower()
        records = [r for r in records if q in r["message"].lower() or q in r["logger"].lower()]
    return records[-limit:]


def demo():
    """Self-check: setup is idempotent, level round-trips, filtering works."""
    setup_logging("DEBUG")
    setup_logging("INFO")  # second call must not add handlers again
    assert set_level("WARNING") == "WARNING"
    assert set_level("bogus") == "INFO"
    log = logging.getLogger("mynes.test")
    log.error("boom alpha")
    log.info("quiet beta")
    assert any("boom alpha" in r["message"] for r in recent())
    assert all(r["level"] == "ERROR" for r in recent(level="ERROR"))
    assert any("alpha" in r["message"] for r in recent(query="alpha"))
    assert not recent(query="nonexistent-zzz")
    print("logsetup demo OK")


if __name__ == "__main__":
    demo()
