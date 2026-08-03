"""System tray / menu bar icon.

Gives MyNeS a home outside the browser: the device count and unread alerts are
visible at a glance, and a scan is two clicks away. On Windows it sits in the
notification area, on macOS in the menu bar, on Linux in the AppIndicator tray.

    python -m mynes.tray                       # start the server + the icon
    python -m mynes.tray --connect http://nas.local:5883   # icon only

Requires the optional extra:  pip install "mynes[tray]"

ponytail: the icon is drawn with Pillow at runtime rather than shipping a PNG
per state - three colours x two badge states is six files we would have to keep
in sync with the theme.
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser

POLL_SECONDS = 30
TIMEOUT = 5

# Matches the web design system's semantic colours.
COLOURS = {
    "ok": (22, 168, 98),        # --success-bg
    "warning": (217, 155, 9),   # --warning-bg
    "critical": (220, 53, 69),  # --danger-bg
    "offline": (107, 118, 137), # --text-secondary
}


def _draw_icon(state: str, badge: bool):
    """A network glyph: three nodes joined to a bus, plus an alert dot."""
    from PIL import Image, ImageDraw

    size = 64
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    colour = COLOURS.get(state, COLOURS["offline"])

    # bus + risers
    d.line([(14, 34), (50, 34)], fill=colour, width=5)
    d.line([(32, 34), (32, 20)], fill=colour, width=5)
    for x in (14, 32, 50):
        d.line([(x, 34), (x, 42)], fill=colour, width=5)

    # top node + three leaf nodes
    d.rounded_rectangle([24, 6, 40, 20], radius=4, fill=colour)
    for x in (14, 32, 50):
        d.rounded_rectangle([x - 8, 42, x + 8, 58], radius=4, fill=colour)

    if badge:
        d.ellipse([44, 0, 64, 20], fill=COLOURS["critical"])
        d.ellipse([48, 4, 60, 16], fill=(255, 255, 255, 255))
        d.ellipse([50, 6, 58, 14], fill=COLOURS["critical"])

    return img


class TrayApp:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.health: dict = {}
        self.error: str | None = None
        self.icon = None
        self._stop = threading.Event()

    # -- server calls -----------------------------------------------------
    def _get(self, path: str, method: str = "GET"):
        req = urllib.request.Request(f"{self.base_url}{path}", method=method)
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:  # noqa: S310 - user's own server
            return json.loads(r.read().decode())

    def refresh(self):
        try:
            self.health = self._get("/api/health")
            self.error = None
        except (urllib.error.URLError, OSError, ValueError) as e:
            self.error = str(e)
            self.health = {}
        if self.icon:
            self.icon.icon = _draw_icon(self.state(), self.unread() > 0)
            self.icon.title = self.tooltip()
            self.icon.update_menu()

    def state(self) -> str:
        if self.error:
            return "offline"
        alerts = self.health.get("alerts") or {}
        if (alerts.get("by_severity") or {}).get("critical"):
            return "critical"
        if alerts.get("unread"):
            return "warning"
        return "ok"

    def unread(self) -> int:
        return (self.health.get("alerts") or {}).get("unread", 0)

    def tooltip(self) -> str:
        if self.error:
            return f"MyNeS - not reachable at {self.base_url}"
        return f"MyNeS - {self.health.get('devices', 0)} devices, {self.unread()} unread alerts"

    # -- menu actions -----------------------------------------------------
    def _open(self, *_):
        webbrowser.open(self.base_url)

    def _scan_now(self, *_):
        def run():
            try:
                result = self._get("/api/monitoring/run", method="POST")
                self._notify("Scan complete",
                             f"{result.get('devices', 0)} devices, {result.get('alerts', 0)} alerts")
            except (urllib.error.URLError, OSError, ValueError) as e:
                self._notify("Scan failed", str(e))
            self.refresh()

        threading.Thread(target=run, daemon=True).start()
        self._notify("Scanning", "MyNeS is scanning the network...")

    def _mark_read(self, *_):
        try:
            self._get("/api/alerts/read", method="POST")
        except (urllib.error.URLError, OSError, ValueError):
            pass
        self.refresh()

    def _notify(self, title: str, message: str):
        try:
            if self.icon and self.icon.HAS_NOTIFICATION:
                self.icon.notify(message, title)
        except (NotImplementedError, AttributeError):
            print(f"[MyNeS] {title}: {message}")

    def _quit(self, *_):
        self._stop.set()
        if self.icon:
            self.icon.stop()

    # -- menu -------------------------------------------------------------
    def build_menu(self):
        import pystray

        def label_status(_):
            if self.error:
                return f"Not reachable: {self.base_url}"
            return f"{self.health.get('devices', 0)} devices · {self.unread()} unread"

        def label_monitor(_):
            return "Monitoring: on" if self.health.get("monitoring") else "Monitoring: off"

        return pystray.Menu(
            pystray.MenuItem(label_status, self._open, default=True),
            pystray.MenuItem(label_monitor, None, enabled=False),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Open MyNeS", self._open),
            pystray.MenuItem("Scan now", self._scan_now),
            pystray.MenuItem("Mark alerts read", self._mark_read,
                             enabled=lambda _: self.unread() > 0),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Quit", self._quit),
        )

    def _poll_loop(self):
        while not self._stop.is_set():
            self.refresh()
            self._stop.wait(POLL_SECONDS)

    def run(self):
        import pystray

        self.refresh()
        self.icon = pystray.Icon(
            "mynes",
            icon=_draw_icon(self.state(), self.unread() > 0),
            title=self.tooltip(),
            menu=self.build_menu(),
        )
        threading.Thread(target=self._poll_loop, daemon=True).start()
        # Blocks; on macOS this MUST be the main thread, hence the server runs
        # in a background thread rather than the other way round.
        self.icon.run()


def _start_server_thread(port: int):
    from mynes.web.app import app

    def serve():
        app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)

    threading.Thread(target=serve, daemon=True).start()

    base = f"http://127.0.0.1:{port}"
    for _ in range(60):
        try:
            urllib.request.urlopen(f"{base}/api/health", timeout=1).read()
            return base
        except (urllib.error.URLError, OSError):
            time.sleep(0.5)
    print("Server did not come up in time; the icon will show it as unreachable.", file=sys.stderr)
    return base


def main():
    ap = argparse.ArgumentParser(description="MyNeS tray / menu bar icon.")
    ap.add_argument("--connect", metavar="URL",
                    help="attach to an already-running MyNeS instead of starting one")
    ap.add_argument("--port", type=int, default=5883, help="port to serve on when starting one")
    args = ap.parse_args()

    try:
        import pystray  # noqa: F401
        from PIL import Image  # noqa: F401
    except ImportError:
        sys.exit('The tray icon needs extra packages:  pip install "mynes[tray]"')

    base_url = args.connect or _start_server_thread(args.port)
    print(f"MyNeS tray icon running against {base_url}. Use the menu to quit.")
    TrayApp(base_url).run()


def demo():
    """Self-check: icon rendering and state mapping, no GUI, no server."""
    from PIL import Image

    for state in COLOURS:
        for badge in (False, True):
            img = _draw_icon(state, badge)
            assert isinstance(img, Image.Image) and img.size == (64, 64)
            assert img.getextrema()[3][1] > 0, "icon must not be fully transparent"

    app = TrayApp("http://127.0.0.1:1")
    app.error = "boom"
    assert app.state() == "offline" and "not reachable" in app.tooltip()

    app.error = None
    app.health = {"devices": 12, "alerts": {"unread": 0, "by_severity": {"critical": 0}}}
    assert app.state() == "ok" and app.unread() == 0

    app.health = {"devices": 12, "alerts": {"unread": 3, "by_severity": {"critical": 0}}}
    assert app.state() == "warning", app.state()

    app.health = {"devices": 12, "alerts": {"unread": 3, "by_severity": {"critical": 1}}}
    assert app.state() == "critical", "a critical alert must outrank a plain unread count"
    assert "12 devices" in app.tooltip()
    print("tray demo OK")


if __name__ == "__main__":
    if "--self-check" in sys.argv:
        demo()
    else:
        main()
