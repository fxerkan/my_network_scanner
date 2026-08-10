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
import re
import sys
import time
from collections import deque
from pathlib import Path

from mynes.paths import DATA_DIR

LOG_FILE = str(Path(DATA_DIR) / "mynes.log")
_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"
_DATEFMT = "%Y-%m-%d %H:%M:%S"

# Level names the UI offers, coarse-to-fine.
LEVELS = ["ERROR", "WARNING", "INFO", "DEBUG"]

# Strip terminal colour codes (werkzeug's banner, click.echo) so the Logs UI
# doesn't show raw "[31m[1m..." garbage.
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _strip(text: str) -> str:
    return _ANSI.sub("", text or "")


_configured = False


class _RingHandler(logging.Handler):
    """Keep the most recent records in memory for the Logs API to read cheaply."""

    def __init__(self, capacity: int = 4000):
        super().__init__()
        self.buffer: deque = deque(maxlen=capacity)

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.buffer.append({
                "time": self.formatter.formatTime(record, _DATEFMT) if self.formatter else "",
                "level": record.levelname,
                "logger": record.name,
                "message": _strip(record.getMessage()),
            })
        except Exception:  # noqa: BLE001 - logging must never raise into callers
            pass


_ring = _RingHandler()


class _StreamTee:
    """Wrap stdout/stderr so plain print() (used all over this codebase for scan
    and analysis progress) also lands in the Logs UI, not just the terminal.
    Writes straight through to the real stream, then buffers complete lines into
    the ring. ANSI is stripped; the original stream keeps its colours."""

    def __init__(self, real, level: str):
        self._real = real
        self._level = level
        self._buf = ""

    def write(self, text):
        try:
            self._real.write(text)
        except Exception:  # noqa: BLE001
            pass
        try:
            self._buf += text
            while "\n" in self._buf:
                line, self._buf = self._buf.split("\n", 1)
                line = _strip(line).rstrip()
                if line:
                    _ring.buffer.append({
                        "time": time.strftime(_DATEFMT),
                        "level": self._level, "logger": "console", "message": line,
                    })
        except Exception:  # noqa: BLE001
            pass

    def flush(self):
        try:
            self._real.flush()
        except Exception:  # noqa: BLE001
            pass

    def isatty(self):
        return getattr(self._real, "isatty", lambda: False)()

    def __getattr__(self, name):
        return getattr(self._real, name)


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
        # werkzeug logs EVERY request (every static asset, every poll) - that
        # flood drowns the app's own logs. Keep its warnings/errors, drop the
        # per-request 200 access-log spam.
        logging.getLogger("werkzeug").setLevel(logging.WARNING)
        # Capture bare print()/click banners into the ring so scan and analysis
        # progress shows in the Logs UI, not only the terminal.
        if not isinstance(sys.stdout, _StreamTee):
            sys.stdout = _StreamTee(sys.stdout, "INFO")
        if not isinstance(sys.stderr, _StreamTee):
            sys.stderr = _StreamTee(sys.stderr, "WARNING")
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
    # ANSI colour codes are stripped from the stored message.
    log.warning("\x1b[31mred\x1b[0m warn-gamma")
    assert any(r["message"] == "red warn-gamma" for r in recent(query="gamma"))
    # The stdout tee captures writes into the ring (tested directly, since a test
    # runner may reassign the real sys.stdout out from under a global swap).
    import io
    tee = _StreamTee(io.StringIO(), "INFO")
    tee.write("printed \x1b[32mdelta\x1b[0m line\n")
    assert any(r["message"] == "printed delta line" for r in recent(query="delta"))
    print("logsetup demo OK")


if __name__ == "__main__":
    demo()
