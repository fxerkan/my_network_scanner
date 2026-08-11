"""Application logging: a daily-rotated file plus an in-memory ring buffer.

Before this, everything was bare print()/getLogger() to stderr with no file and
no way for the UI to show logs. This wires the root logger to a daily-rotating
file in DATA_DIR and keeps the last N records in memory so the Settings > Logs
tab can read today's logs cheaply. Past days are read back from the rotated
files on disk, so the Logs UI survives a restart instead of showing an empty
buffer (the whole point of a log you can trust).

Files: ``mynes.log`` is today; midnight rollover renames it to
``mynes.log.YYYY-MM-DD`` and starts a fresh one. backupCount keeps a month.

ponytail: parsing the rotated files on demand is enough for one box; if logs
ever need cross-day full-text search, index them into SQLite instead.
"""

from __future__ import annotations

import logging
import logging.handlers
import re
import sys
import threading
import time
from collections import deque
from pathlib import Path

from mynes.paths import DATA_DIR

LOG_FILE = str(Path(DATA_DIR) / "mynes.log")
# Location of the failing code goes into every real record's format so an error
# in the file points at module:function:line, not just a bare message.
_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"
_DATEFMT = "%Y-%m-%d %H:%M:%S"
_DATE_ONLY = "%Y-%m-%d"

# Level names the UI offers, coarse-to-fine.
LEVELS = ["ERROR", "WARNING", "INFO", "DEBUG"]

# Strip terminal colour codes (werkzeug's banner, click.echo) so the Logs UI
# doesn't show raw "[31m[1m..." garbage.
_ANSI = re.compile(r"\x1b\[[0-9;]*m")

# Parse a persisted line back into a record. Logger name is matched non-greedily
# so the first ": " (after the logger) splits name from message, even when the
# message itself contains ": ".
_LINE = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) (\w+) (.+?): (.*)$")


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
            msg = _strip(record.getMessage())
            # An exception's traceback is the whole point of the error record;
            # carry it (and the exception type as a "code") into the UI too.
            code = ""
            if record.exc_info and self.formatter:
                code = getattr(record.exc_info[0], "__name__", "") or ""
                msg = msg + "\n" + _strip(self.formatter.formatException(record.exc_info))
            rec = {
                "time": self.formatter.formatTime(record, _DATEFMT) if self.formatter else "",
                "level": record.levelname,
                "logger": record.name,
                "message": msg,
            }
            # Console (print) lines have no meaningful source location; real
            # records point the user straight at the failing code.
            if record.name != "console":
                rec["location"] = f"{record.module}.{record.funcName}:{record.lineno}"
            if code:
                rec["code"] = code
            self.buffer.append(rec)
        except Exception:  # noqa: BLE001 - logging must never raise into callers
            pass


_ring = _RingHandler()
# print()/click banners are routed through this logger so they reach BOTH the
# rotating file (persistence) and the ring - not just the terminal.
_console_log = logging.getLogger("console")
_tee_guard = threading.local()


class _StreamTee:
    """Wrap stdout/stderr so plain print() (used all over this codebase for scan
    and analysis progress) also lands in the Logs UI and the persistent file,
    not just the terminal. Writes straight through to the real stream first,
    then re-emits complete lines through the ``console`` logger. ANSI is
    stripped for the log; the original stream keeps its colours. A thread-local
    guard stops logging's own error path (which writes to stderr) from
    recursing back through this tee."""

    def __init__(self, real, levelno: int):
        self._real = real
        self._levelno = levelno
        self._buf = ""

    def write(self, text):
        try:
            self._real.write(text)
        except Exception:  # noqa: BLE001
            pass
        if getattr(_tee_guard, "busy", False):
            return
        try:
            self._buf += text
            while "\n" in self._buf:
                line, self._buf = self._buf.split("\n", 1)
                line = _strip(line).rstrip()
                if line:
                    _tee_guard.busy = True
                    try:
                        _console_log.log(self._levelno, line)
                    finally:
                        _tee_guard.busy = False
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
    """Attach a daily-rotating file handler + the ring buffer to the root logger once."""
    global _configured
    root = logging.getLogger()
    fmt = logging.Formatter(_FORMAT, _DATEFMT)
    _ring.setFormatter(fmt)

    if not _configured:
        Path(DATA_DIR).mkdir(parents=True, exist_ok=True)
        fileh = logging.handlers.TimedRotatingFileHandler(
            LOG_FILE, when="midnight", backupCount=30, encoding="utf-8")
        fileh.suffix = _DATE_ONLY  # mynes.log.2026-08-10
        fileh.setFormatter(fmt)
        root.addHandler(fileh)
        root.addHandler(_ring)
        # Scapy stays quiet regardless of the app level.
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
        # werkzeug logs EVERY request (every static asset, every poll) - that
        # flood drowns the app's own logs. Keep its warnings/errors, drop the
        # per-request 200 access-log spam.
        logging.getLogger("werkzeug").setLevel(logging.WARNING)
        # Capture bare print()/click banners into the file+ring so scan and
        # analysis progress shows in the Logs UI, not only the terminal.
        if not isinstance(sys.stdout, _StreamTee):
            sys.stdout = _StreamTee(sys.stdout, logging.INFO)
        if not isinstance(sys.stderr, _StreamTee):
            sys.stderr = _StreamTee(sys.stderr, logging.WARNING)
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


def _filter(records: list, level: str | None, query: str | None) -> list:
    if level and level.upper() in LEVELS:
        floor = LEVELS.index(level.upper())
        allowed = set(LEVELS[: floor + 1])
        records = [r for r in records if r["level"] in allowed]
    if query:
        q = query.lower()
        records = [r for r in records
                   if q in r["message"].lower() or q in r["logger"].lower()]
    return records


def recent(limit: int = 500, level: str | None = None, query: str | None = None) -> list:
    """Most-recent-last records from today's live ring, optionally filtered."""
    return _filter(list(_ring.buffer), level, query)[-limit:]


def available_dates() -> list:
    """Dates (newest first) that have a log to show - today plus rotated files."""
    dates = {time.strftime(_DATE_ONLY)}  # today is always available (the ring)
    for f in Path(DATA_DIR).glob("mynes.log.*"):
        suffix = f.name[len("mynes.log."):]
        if re.fullmatch(r"\d{4}-\d\d-\d\d", suffix):
            dates.add(suffix)
    return sorted(dates, reverse=True)


def _parse_file(path: Path) -> list:
    """Parse a persisted log file into records. Non-matching lines (traceback
    continuations) fold into the previous record's message."""
    records: list = []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                line = _strip(raw.rstrip("\n"))
                m = _LINE.match(line)
                if m:
                    ts, lvl, logger, msg = m.groups()
                    records.append({"time": ts, "level": lvl,
                                    "logger": logger, "message": msg})
                elif records:
                    records[-1]["message"] += "\n" + line
    except FileNotFoundError:
        return []
    return records


def for_date(date: str, limit: int = 500, level: str | None = None,
             query: str | None = None) -> list:
    """Records for a given YYYY-MM-DD. Today comes from the live ring; past days
    are read back from their rotated file on disk."""
    if not re.fullmatch(r"\d{4}-\d\d-\d\d", date or ""):
        return recent(limit, level, query)
    if date == time.strftime(_DATE_ONLY):
        return recent(limit, level, query)
    records = _parse_file(Path(LOG_FILE + "." + date))
    return _filter(records, level, query)[-limit:]


def demo():
    """Self-check: setup is idempotent, level round-trips, filtering + file
    parsing + the console tee all work."""
    setup_logging("DEBUG")
    setup_logging("INFO")  # second call must not add handlers again
    assert set_level("WARNING") == "WARNING"
    assert set_level("bogus") == "INFO"
    set_level("DEBUG")
    log = logging.getLogger("mynes.test")
    log.error("boom alpha")
    log.info("quiet beta")
    assert any("boom alpha" in r["message"] for r in recent())
    assert all(r["level"] == "ERROR" for r in recent(level="ERROR"))
    assert any("alpha" in r["message"] for r in recent(query="alpha"))
    assert not recent(query="nonexistent-zzz")
    # Real records carry a source location; the UI shows where it happened.
    assert any("location" in r for r in recent(query="alpha"))
    # An exception record carries its traceback and type "code".
    try:
        raise ValueError("kaboom epsilon")
    except ValueError:
        log.exception("caught it")
    assert any(r.get("code") == "ValueError" and "Traceback" in r["message"]
               for r in recent(query="epsilon"))
    # ANSI colour codes are stripped from the stored message.
    log.warning("\x1b[31mred\x1b[0m warn-gamma")
    assert any(r["message"] == "red warn-gamma" for r in recent(query="gamma"))
    # The stdout tee routes writes through the console logger into the ring.
    tee = _StreamTee(sys.__stdout__, logging.INFO)
    tee.write("printed \x1b[32mdelta\x1b[0m line\n")
    assert any(r["message"] == "printed delta line" for r in recent(query="delta"))
    # Persisted-file parsing round-trips a line (incl. a ": " inside the message)
    # and folds a traceback continuation into the previous record.
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as tf:
        tf.write("2026-08-10 09:00:00 INFO console: OUI database loaded: 40126 entries\n")
        tf.write("2026-08-10 09:00:01 ERROR mynes.x: boom\n")
        tf.write("Traceback (most recent call last):\n")
        tf.write("  File \"x.py\", line 1, in f\n")
        name = tf.name
    parsed = _parse_file(Path(name))
    assert parsed[0]["logger"] == "console"
    assert parsed[0]["message"] == "OUI database loaded: 40126 entries"
    assert "Traceback" in parsed[1]["message"]
    Path(name).unlink()
    assert time.strftime(_DATE_ONLY) in available_dates()
    print("logsetup demo OK")


if __name__ == "__main__":
    demo()
