"""Bluetooth / BLE discovery via bleak (optional dependency).

BLE devices have no IP, so they never show up in an ARP or nmap sweep - this is
the only way MyNeS sees trackers, sensors, watches, headphones and BLE-based
smart-home gear. Devices are keyed by their Bluetooth address instead of a MAC
on the IP network; the merger treats them as standalone entries.

Requires: pip install "mynes[bluetooth]" and OS Bluetooth permission
(macOS: Terminal needs Bluetooth access in System Settings > Privacy).

In a container this also needs the host's D-Bus system bus socket bind-mounted
in - see `available()` and deploy/docker-compose.yml. It does NOT need a USB
dongle passed through: on Linux bleak never touches the adapter directly, it
asks BlueZ over D-Bus, and BlueZ runs on the host.
"""

from __future__ import annotations

import os
import stat
import sys

from mynes.discovery.base import DiscoveredDevice, DiscoveryBackend

# Where D-Bus puts the system bus socket on every mainstream Linux. bleak talks
# to BlueZ through it; without it the adapter is unreachable no matter how
# healthy `hciconfig` looks on the host.
DBUS_SYSTEM_SOCKET = "/run/dbus/system_bus_socket"

# Bluetooth SIG company identifiers seen most often in a home.
COMPANY_IDS = {
    0x004C: "Apple",
    0x0006: "Microsoft",
    0x00E0: "Google",
    0x0075: "Samsung",
    0x0157: "Huami/Amazfit",
    0x038F: "Xiaomi",
    0x0499: "Ruuvi",
    0x02E5: "Espressif",
    0x0059: "Nordic Semiconductor",
    0x0171: "Amazon",
    0x0087: "Garmin",
    0x000F: "Broadcom",
    0x0131: "Cypress",
}

# Item-tracker service UUIDs (Samsung Galaxy SmartTag / SmartThings Find).
TRACKER_SERVICE_UUIDS = ("0000fd5a", "0000fd59", "0000fd6f")

# Names item-trackers advertise, or that owners commonly give them.
TRACKER_NAME_HINTS = ("airtag", "smarttag", "smart tag", "tile", "chipolo", "galaxy smarttag")

# --- Apple "Find My" / Continuity advertisement decode -----------------------
# Apple's BLE manufacturer-data (company 0x004C) is a run of TLVs:
# [type][len][value...]. The type byte says which message it is. We decode:
#   0x12 Offline Finding (Find My network) - AirTags & Find My accessories, the
#        one Apple keeps closed to other vendors and the reason this exists.
#   0x07 Proximity Pairing - AirPods/Beats, carries a 2-byte model id.
#   0x10/0x0C/... Continuity - an iPhone/iPad/Mac/Watch is nearby (no model).
# All of this is read from the public advert alone: no Apple ID, no cloud - the
# same passive data anyone in BLE range already sees. (Locating your *own* tags
# would need Apple-account auth + report decryption, which is out of scope.)
APPLE_CID = 0x004C

# Find My status byte: bits 4-5 = device class, bits 6-7 = battery bucket.
# Bit layout from malmeloo/FindMy.py (scanner.py OfflineFindingDevice), cross-
# checked against live AirTag / iPhone / iPad captures.
_FINDMY_TYPE = {
    0b00: "Apple Device",       # generic / status not exposing a class
    0b01: "Apple AirTag",
    0b10: "Bluetooth Tracker",  # licensed 3rd-party Find My accessory
    0b11: "Headphones",         # AirPods advertising via Find My
}
_FINDMY_BATTERY = {0b00: "Full", 0b01: "Medium", 0b10: "Low", 0b11: "Very Low"}

# AirPods/Beats model ids from the 0x07 Proximity Pairing message (2 bytes).
# Community-sourced (furiousMAC/continuity); matched in both byte orders.
# ponytail: partial table, add rows as new models appear - unknowns fall back
# to a plain "AirPods".
_AIRPODS_MODELS = {
    0x0220: "AirPods", 0x0F20: "AirPods (2nd gen)", 0x1320: "AirPods (3rd gen)",
    0x1920: "AirPods (4th gen)", 0x1B20: "AirPods (4th gen, ANC)",
    0x0E20: "AirPods Pro", 0x1420: "AirPods Pro (2nd gen)",
    0x2420: "AirPods Pro (2nd gen, USB-C)",
    0x0A20: "AirPods Max", 0x1F20: "AirPods Max (USB-C)",
    0x0320: "Powerbeats 3", 0x0B20: "Powerbeats Pro", 0x0C20: "Beats Solo 3",
    0x1120: "Beats Studio 3", 0x0520: "BeatsX", 0x1020: "Beats Flex",
    0x0620: "Beats Solo Pro", 0x1720: "Beats Studio Buds",
    0x1D20: "Beats Studio Buds+", 0x1E20: "Beats Fit Pro",
}


def _apple_tlvs(blob):
    """Walk Apple's [type][len][value] run, yielding (type, value) pairs."""
    i, n = 0, len(blob)
    while i + 2 <= n:
        t, ln = blob[i], blob[i + 1]
        val = blob[i + 2:i + 2 + ln]
        if len(val) < ln:  # truncated advert, stop rather than misread
            break
        yield t, val
        i += 2 + ln


def identify_apple_ble(manufacturer_data):
    """Classify an Apple BLE advert, or None if it is not one we decode.

    Returns {device_type, name, find_my, battery, state}. `name` is a model
    string only when the advert carries one (AirPods). Everything is derived
    from the advertisement alone - no account, no network call.
    """
    blob = (manufacturer_data or {}).get(APPLE_CID)
    if not blob:
        return None
    msgs = dict(_apple_tlvs(blob))

    # Find My (offline finding) wins - it is the whole point of this feature.
    of = msgs.get(0x12)
    if of:
        status = of[0]
        return {
            "device_type": _FINDMY_TYPE[(status >> 4) & 0b11],
            "name": None,
            "find_my": True,
            "battery": _FINDMY_BATTERY[(status >> 6) & 0b11],
            # 25-byte body = separated from owner (full key), 2-byte = nearby.
            "state": "separated" if len(of) >= 0x19 else "nearby",
        }

    # AirPods/Beats advertising their model (case open / pairing).
    pp = msgs.get(0x07)
    if pp and len(pp) >= 3:
        model = _AIRPODS_MODELS.get(int.from_bytes(pp[1:3], "big")) or \
            _AIRPODS_MODELS.get(int.from_bytes(pp[1:3], "little"))
        return {"device_type": "Headphones", "name": model or "AirPods",
                "find_my": False, "battery": None, "state": None}

    # Continuity (Nearby Info / Handoff / AirDrop / AirPlay): an Apple phone,
    # tablet, Mac or watch is here, but the payload carries no model. Honest
    # generic label - better than the "Bluetooth Device" it used to get.
    if msgs.keys() & {0x10, 0x0C, 0x05, 0x0F, 0x09, 0x0A}:
        return {"device_type": "Apple Device", "name": None,
                "find_my": False, "battery": None, "state": None}
    return None


def classify_ble(name, vendor, manufacturer_data, service_uuids, fallback):
    """Best-effort device_type from a BLE advertisement.

    Trackers are the point here: Apple Find My devices (AirTag / AirPods /
    licensed accessories) are decoded from the 0x12 offline-finding status byte
    via identify_apple_ble(); a Galaxy SmartTag advertises a SmartThings service
    UUID. Everything else falls back to the caller's service-hint guess, then a
    name sniff, then a generic Apple label for plain Continuity devices.
    """
    low = (name or "").lower()
    apple = identify_apple_ble(manufacturer_data)
    # A specific Apple type (AirTag/AirPods/tracker) beats every other signal.
    if apple and apple["device_type"] != "Apple Device":
        return apple["device_type"]
    uuids = [str(u)[:8].lower() for u in (service_uuids or [])]
    if any(u in TRACKER_SERVICE_UUIDS for u in uuids):
        return "Samsung SmartTag"
    if "airtag" in low:
        return "Apple AirTag"
    if "smarttag" in low or "smart tag" in low:
        return "Samsung SmartTag"
    if "tile" in low:
        return "Tile Tracker"
    if any(k in low for k in TRACKER_NAME_HINTS):
        return "Bluetooth Tracker"
    if any(k in low for k in ("airpods", "buds", "headphone", "headset", "wh-", "wf-")):
        return "Headphones"
    if any(k in low for k in ("watch", "band", "fit", "amazfit")):
        return "Wearable"
    if apple:  # plain Continuity iPhone/iPad/Mac - after name sniffs, before generic
        return apple["device_type"]
    return fallback or "Bluetooth Device"


# 16-bit GATT service UUIDs worth naming.
SERVICE_HINTS = {
    "0000180f": ("Battery Service", None),
    "0000180d": ("Heart Rate", "Wearable"),
    "0000181a": ("Environmental Sensing", "Sensor"),
    "0000fe95": ("Xiaomi MiBeacon", "Sensor"),
    "0000fd6f": ("Exposure Notification", "Smartphone"),
    "0000fe9f": ("Google Fast Pair", None),
    "0000feaa": ("Eddystone Beacon", "Beacon"),
    "0000fe07": ("Microsoft Swift Pair", None),
    "0000ffe0": ("Serial (HM-10)", "IoT Device"),
    "0000fef3": ("Google", None),
}


def _is_socket(path: str) -> bool:
    """Socket, not merely present.

    Deliberately not os.path.exists: docker creates an empty *directory* at the
    source of a bind mount that does not exist on the host, so a typo'd or
    Docker-Desktop-shaped mount leaves a plausible-looking path that can never
    be connected to. Checking the type turns that into a clear reason.
    """
    try:
        return stat.S_ISSOCK(os.stat(path).st_mode)
    except OSError:
        return False


def _dbus_system_bus_reachable() -> bool:
    """Is there a system bus socket to talk to?

    DBUS_SYSTEM_BUS_ADDRESS wins when set, since that is how an operator moves
    the bus. Its value is a semicolon-separated list of addresses; we can only
    verify the unix ones, so anything else (tcp:, autolaunch:) is taken on faith
    rather than reported as broken.
    """
    address = os.environ.get("DBUS_SYSTEM_BUS_ADDRESS")
    if not address:
        return _is_socket(DBUS_SYSTEM_SOCKET)

    checkable = False
    for candidate in address.split(";"):
        for part in candidate.split(","):
            if part.startswith("unix:path="):
                checkable = True
                if _is_socket(part.split("=", 1)[1]):
                    return True
    return not checkable


class BluetoothBackend(DiscoveryBackend):
    name = "ble"
    requires = ("bleak",)

    def available(self) -> tuple[bool, str]:
        """(usable?, reason), with the reason an operator can act on.

        bleak imports fine without a reachable bus and only fails once a scan is
        already running, where the error surfaces as a bare
        "[Errno 2] No such file or directory". That reported `ble: ok, count 0`
        - indistinguishable from "scanned, found nothing" - so the missing mount
        is caught here instead, where /api/capabilities can say so.
        """
        ok, reason = super().available()
        if not ok:
            return ok, reason
        # Only Linux routes through D-Bus. macOS uses CoreBluetooth and Windows
        # WinRT, neither of which has a socket to look for.
        if sys.platform.startswith("linux") and not _dbus_system_bus_reachable():
            return False, (
                f"no D-Bus system bus - bind-mount {DBUS_SYSTEM_SOCKET} "
                "into the container (host BlueZ is what actually scans)"
            )
        return True, "ok"

    def discover(self, timeout: float = 8.0) -> list[DiscoveredDevice]:
        import asyncio

        from bleak import BleakScanner

        async def scan():
            return await BleakScanner.discover(timeout=timeout, return_adv=True)

        try:
            results = asyncio.run(scan())
        except RuntimeError:
            # Already inside a loop (e.g. called from an async web handler).
            loop = asyncio.new_event_loop()
            try:
                results = loop.run_until_complete(scan())
            finally:
                loop.close()

        devices = []
        for address, (ble_device, adv) in results.items():
            vendor = None
            for cid in (adv.manufacturer_data or {}):
                vendor = COMPANY_IDS.get(cid)
                if vendor:
                    break

            services, dtype = [], None
            for uuid in adv.service_uuids or []:
                label, hint = SERVICE_HINTS.get(uuid[:8].lower(), (None, None))
                if label:
                    services.append(label)
                dtype = dtype or hint

            apple = identify_apple_ble(adv.manufacturer_data)
            name = adv.local_name or ble_device.name
            if not name and apple and apple.get("name"):
                name = apple["name"]  # AirPods etc. rarely advertise a name
            device_type = classify_ble(
                name, vendor, adv.manufacturer_data, adv.service_uuids, dtype
            )

            attributes = {
                "bluetooth": True,
                "rssi": adv.rssi,
                "tx_power": adv.tx_power,
                "service_uuids": list(adv.service_uuids or []),
                "manufacturer_ids": [hex(c) for c in (adv.manufacturer_data or {})],
            }
            if apple and apple["find_my"]:
                services.append("Find My")
                attributes["find_my"] = True
                attributes["find_my_state"] = apple["state"]
                if apple["battery"]:
                    attributes["battery"] = apple["battery"]

            devices.append(
                DiscoveredDevice(
                    source="ble",
                    mac=address,
                    name=name,
                    vendor=vendor,
                    device_type=device_type,
                    services=services or ["BLE"],
                    attributes=attributes,
                )
            )
        return devices


def discover(timeout: float = 8.0) -> list[DiscoveredDevice]:
    return BluetoothBackend().safe_discover(timeout=timeout)


def demo():
    md = lambda h: {0x004C: bytes.fromhex(h)}
    # Real captures from a live room, validated against the FindMy.py decode:
    # AirTag in nearby state (status 0xd0 -> class 01, battery Very Low). The
    # owner named it "Laptop Çantası" - the AirTag lives in a laptop bag.
    assert classify_ble("Laptop Çantası", "Apple", md("1202d003"), [], None) == "Apple AirTag"
    air = identify_apple_ble(md("1202d003"))
    assert air["find_my"] and air["battery"] == "Very Low" and air["state"] == "nearby", air
    # Find My device with status byte 0 -> generic Apple, NOT an AirTag (the old
    # code called every 0x12 an AirTag; this is the bug the goal called out).
    assert classify_ble(None, "Apple", md("12020001"), [], None) == "Apple Device"
    # Continuity Nearby Info: an iPhone / iPad. No model in the payload, so an
    # honest generic label instead of "Bluetooth Device".
    assert classify_ble("iPhonErkan", "Apple", md("10073e1fe813760a38"), [], None) == "Apple Device"
    assert classify_ble("FX iPad Mini", "Apple", md("10050c1c960dc6"), [], None) == "Apple Device"
    # AirPods Pro advertising its model on the 0x07 proximity-pairing message.
    pods = identify_apple_ble({0x004C: b"\x07\x19\x01\x0e\x20" + b"\x00" * 22})
    assert pods["device_type"] == "Headphones" and pods["name"] == "AirPods Pro", pods
    # Separated AirTag: full 25-byte offline-finding frame, status class 01.
    sep = identify_apple_ble({0x004C: b"\x12\x19" + b"\x10" + b"\x00" * 24})
    assert sep["device_type"] == "Apple AirTag" and sep["state"] == "separated", sep
    # Non-Apple trackers unchanged.
    assert classify_ble("Tag", "Samsung", {}, ["0000fd5a-0000-1000-8000-00805f9b34fb"], None) == "Samsung SmartTag"
    assert classify_ble("Tile Slim", None, {}, [], None) == "Tile Tracker"
    assert classify_ble("FX AirPods Pro", "Apple", {}, [], None) == "Headphones"
    assert classify_ble("Galaxy Watch", "Samsung", {}, [], None) == "Wearable"
    assert classify_ble("FX Scooter Ninebot", None, {}, [], None) == "Bluetooth Device"
    print("bluetooth classify_ble: ok")


if __name__ == "__main__":
    demo()
    found = discover(10.0)
    print(f"{len(found)} BLE devices")
    for d in found:
        print(f"{d.mac:<20} {d.name or '?':<28} rssi={d.attributes.get('rssi')} {', '.join(d.services)}")
