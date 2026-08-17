#!/usr/bin/env python3
"""Blur MAC addresses (and BLE identifiers) out of screenshots before they ship.

Any image embedded in the CHANGELOG / README must not leak a real device MAC.
This OCRs an image, finds MAC-shaped and BLE-UUID-shaped tokens, and Gaussian-
blurs their bounding boxes in place.

    python scripts/redact_macs.py assets/screenshots/*.png
    python scripts/redact_macs.py --check assets/screenshots/home-view.png

Needs the `tesseract` binary (brew install tesseract); it is called over a
subprocess so there is no Python OCR dependency. `--check` only reports what it
would blur (exit 1 if anything found) - handy in CI or a pre-commit hook.

ponytail: OCR is a heuristic. It catches the well-rendered `xx:xx:..`/UUID
tokens in these UI screenshots; eyeball the result. The fuzzy pass widens the
net for colons OCR misreads. Upgrade path: a second OCR psm pass if a miss shows.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

from PIL import Image, ImageFilter

# A clean MAC (aa:bb:cc:dd:ee:ff / aa-bb-...) or a BLE/CoreBluetooth UUID
# (8-4-4-4-12 hex). Both identify a device and must never ship.
MAC = re.compile(r"([0-9A-Fa-f]{2}[:\-]){4,5}[0-9A-Fa-f]{2}")
UUID = re.compile(r"[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}")


def _is_maclike(tok: str) -> bool:
    """Catch tokens OCR mangled - lots of colons and mostly hex is enough."""
    if MAC.search(tok) or UUID.search(tok):
        return True
    core = tok.strip()
    if core.count(":") >= 4:
        hexish = sum(c in "0123456789abcdefABCDEF:-" for c in core)
        return hexish / max(len(core), 1) > 0.8
    return False


def _boxes(path: Path) -> list[tuple[int, int, int, int, str]]:
    """(left, top, w, h, text) for every OCR word that looks like a MAC."""
    out = subprocess.run(
        ["tesseract", str(path), "stdout", "--psm", "6", "tsv"],
        capture_output=True, text=True, check=True,
    ).stdout
    hits = []
    for line in out.splitlines()[1:]:
        f = line.split("\t")
        if len(f) < 12:
            continue
        text = f[11]
        if text and _is_maclike(text):
            left, top, w, h = (int(f[i]) for i in (6, 7, 8, 9))
            hits.append((left, top, w, h, text))
    return hits


def redact(path: Path, check: bool = False) -> int:
    hits = _boxes(path)
    if not hits:
        return 0
    if check:
        for left, top, w, h, text in hits:
            print(f"  {path.name}: {text!r} at ({left},{top},{w}x{h})")
        return len(hits)
    img = Image.open(path).convert("RGB")
    for left, top, w, h, _ in hits:
        pad = max(4, h // 3)
        box = (max(0, left - pad), max(0, top - pad),
               min(img.width, left + w + pad), min(img.height, top + h + pad))
        region = img.crop(box).filter(ImageFilter.GaussianBlur(radius=max(6, h // 2)))
        img.paste(region, box)
    img.save(path)
    return len(hits)


def main(argv: list[str]) -> int:
    check = "--check" in argv
    paths = [Path(a) for a in argv if not a.startswith("--")]
    if not paths:
        print(__doc__)
        return 2
    total = 0
    for p in paths:
        n = redact(p, check=check)
        total += n
        verb = "would blur" if check else "blurred"
        print(f"{p}: {verb} {n} MAC/UUID region(s)")
    if check and total:
        return 1  # non-zero so a hook/CI can fail on a leak
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
