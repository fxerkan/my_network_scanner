"""_rotate_backup is the safety net that made the '29 devices reported as 2'
data loss recoverable: it snapshots lan_devices.json before any overwrite that
would shrink it. Tested without a network or a full scanner instance."""

import json
import os
import glob

from mynes.core.scanner import LANScanner


def _write(path, n):
    json.dump([{"ip": f"10.0.0.{i}", "mac": f"aa:bb:cc:00:00:{i:02x}"} for i in range(n)],
              open(path, "w"))


def test_backup_on_shrink(tmp_path):
    f = str(tmp_path / "lan_devices.json")
    _write(f, 5)
    bdir = tmp_path / "backups"

    # A write that shrinks the store (5 -> 3) always snapshots the good file.
    LANScanner._rotate_backup(f, new_count=3)
    baks = sorted(glob.glob(str(bdir / "lan_devices.json.*.bak")))
    assert len(baks) == 1, baks
    assert len(json.load(open(baks[0]))) == 5   # the pre-shrink 5 devices are safe

    # A non-shrinking write right after does NOT churn a second backup (deduped
    # to one per hour), so steady scans don't spam the backups dir.
    LANScanner._rotate_backup(f, new_count=5)
    assert len(glob.glob(str(bdir / "*.bak"))) == 1


def test_backup_missing_file_is_noop(tmp_path):
    # Nothing to snapshot before the first save - must not raise or create dirs.
    LANScanner._rotate_backup(str(tmp_path / "nope.json"), new_count=0)
    assert not os.path.exists(tmp_path / "backups")


def test_backup_prunes_to_keep(tmp_path):
    f = str(tmp_path / "lan_devices.json")
    bdir = tmp_path / "backups"
    bdir.mkdir()
    # Pre-seed more stale backups than we keep; a shrink write prunes the oldest.
    for i in range(6):
        (bdir / f"lan_devices.json.2026010{i}-000000.bak").write_text("[]")
    _write(f, 4)
    LANScanner._rotate_backup(f, new_count=1, keep=3)
    assert len(glob.glob(str(bdir / "*.bak"))) == 3


if __name__ == "__main__":
    import tempfile
    import pathlib
    for t in (test_backup_on_shrink, test_backup_missing_file_is_noop, test_backup_prunes_to_keep):
        with tempfile.TemporaryDirectory() as d:
            t(pathlib.Path(d))
    print("backup rotation ok")
