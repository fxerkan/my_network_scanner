#!/usr/bin/env python3
"""Generate the raster assets app stores ask for, from what is already in assets/.

    python scripts/make_store_assets.py

Produces:
    assets/icon.png            256x256 - Unraid / Portainer / Cosmos / CasaOS raster fallback
    assets/icon-128.png        128x128 - Home Assistant add-on
    assets/store/1..3.jpg      1920x1080 - Umbrel gallery (exact size, it is enforced)

The icon is redrawn from the shapes in assets/logo.svg rather than rasterised by a library,
so this needs no SVG dependency. Keep the two in sync if the logo changes.

Screenshots are letterboxed onto a brand-coloured canvas rather than cropped: cropping a
tall UI screenshot to 16:9 cuts off the part that makes it worth showing.

Run it again after replacing a screenshot; it is idempotent.
"""

import sys
from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / "assets"

BRAND = (32, 73, 224)  # --brand / #2049e0, same blue as assets/logo.svg
GALLERY = ["home-view.png", "graph-view.png", "monitoring-alerts.png"]

# assets/logo.svg, verbatim: viewBox 0 0 32 32, then (x, y, w, h, corner-radius) in white.
LOGO_VIEWBOX = 32
LOGO_SHAPES = [
    (12, 4, 8, 7, 2),
    (3, 21, 8, 7, 2),
    (21, 21, 8, 7, 2),
    (15, 11, 2, 4, 0),
    (6, 15, 20, 2, 1),
    (6, 15, 2, 7, 0),
    (24, 15, 2, 7, 0),
]
LOGO_CORNER = 7  # the rx on the background rect


def render_logo(px: int) -> Image.Image:
    """Draw assets/logo.svg at px x px. Supersampled 4x, then downsampled for clean edges."""
    ss = 4
    size = px * ss
    scale = size / LOGO_VIEWBOX
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.rounded_rectangle([0, 0, size - 1, size - 1], radius=LOGO_CORNER * scale, fill=BRAND + (255,))
    for x, y, w, h, r in LOGO_SHAPES:
        box = [x * scale, y * scale, (x + w) * scale - 1, (y + h) * scale - 1]
        if r:
            draw.rounded_rectangle(box, radius=r * scale, fill=(255, 255, 255, 255))
        else:
            draw.rectangle(box, fill=(255, 255, 255, 255))
    return img.resize((px, px), Image.LANCZOS)


def contain(img: Image.Image, size: tuple, background) -> Image.Image:
    """Fit img inside size, centred, on a background canvas. Never crops, never distorts."""
    canvas = Image.new("RGBA", size, background)
    scaled = img.copy()
    scaled.thumbnail(size, Image.LANCZOS)
    canvas.paste(scaled, ((size[0] - scaled.width) // 2, (size[1] - scaled.height) // 2), scaled)
    return canvas


def main() -> int:
    for px in (256, 128):
        out = ASSETS / ("icon.png" if px == 256 else f"icon-{px}.png")
        render_logo(px).save(out, optimize=True)
        print(f"{out.relative_to(ROOT)}  {px}x{px}")

    store = ASSETS / "store"
    store.mkdir(exist_ok=True)
    for n, name in enumerate(GALLERY, start=1):
        shot = ASSETS / "screenshots" / name
        if not shot.exists():
            print(f"missing {shot}, skipping {n}.jpg", file=sys.stderr)
            continue
        out = store / f"{n}.jpg"
        frame = contain(Image.open(shot).convert("RGBA"), (1920, 1080), BRAND + (255,))
        frame.convert("RGB").save(out, quality=88, optimize=True)
        print(f"{out.relative_to(ROOT)}  1920x1080  <- {name}")

    return 0


def demo() -> None:
    """Self-check: contain() never crops, never distorts, always returns the exact size."""
    tall = Image.new("RGBA", (400, 1000), (255, 0, 0, 255))
    out = contain(tall, (1920, 1080), BRAND + (255,))
    assert out.size == (1920, 1080), out.size
    # Aspect preserved: a 400x1000 source scaled to fit 1080 height is 432 wide, so the
    # canvas edges stay brand-coloured and the image is centred.
    assert out.getpixel((0, 0))[:3] == BRAND, out.getpixel((0, 0))
    assert out.getpixel((960, 540))[:3] == (255, 0, 0), out.getpixel((960, 540))

    wide = Image.new("RGBA", (4000, 100), (0, 255, 0, 255))
    assert contain(wide, (256, 256), (0, 0, 0, 0)).size == (256, 256)

    # The icon is brand blue in the corners-ish and white where the logo's centre bar sits.
    icon = render_logo(256)
    assert icon.size == (256, 256), icon.size
    assert icon.getpixel((128, 128))[:3] == (255, 255, 255), icon.getpixel((128, 128))  # the 6,15 bar
    assert icon.getpixel((128, 20))[:3] == BRAND, icon.getpixel((128, 20))  # above the top node
    print("demo ok")


if __name__ == "__main__":
    if "--demo" in sys.argv:
        demo()
    else:
        sys.exit(main())
