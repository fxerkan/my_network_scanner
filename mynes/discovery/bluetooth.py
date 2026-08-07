"""Bluetooth / BLE discovery via bleak (optional dependency).

BLE devices have no IP, so they never show up in an ARP or nmap sweep - this is
the only way MyNeS sees trackers, sensors, watches, headphones and BLE-based
smart-home gear. Devices are keyed by their Bluetooth address instead of a MAC
on the IP network; the merger treats them as standalone entries.

Requires: pip install "mynes[bluetooth]" and OS Bluetooth permission
(macOS: Terminal needs Bluetooth access in System Settings > Privacy).
"""

from __future__ import annotations

from mynes.discovery.base import DiscoveredDevice, DiscoveryBackend

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


def classify_ble(name, vendor, manufacturer_data, service_uuids, fallback):
    """Best-effort device_type from a BLE advertisement.

    Trackers are the point here: an AirTag separated from its owner broadcasts
    Apple's Find My "offline finding" payload (manufacturer type byte 0x12), and
    a Galaxy SmartTag advertises a SmartThings service UUID. Both are otherwise
    just "Apple"/"Samsung" BLE blips. Everything else falls back to the caller's
    service-hint guess, then a name sniff for headphones/watches.
    ponytail: near-owner AirTags advertise 0x10, not 0x12, and go unclassified -
    upgrade with the full Find My status-byte table if that matters.
    """
    low = (name or "").lower()
    apple = (manufacturer_data or {}).get(0x004C)
    if apple and apple[:1] == b"\x12":
        return "Bluetooth Tracker"
    uuids = [str(u)[:8].lower() for u in (service_uuids or [])]
    if any(u in TRACKER_SERVICE_UUIDS for u in uuids):
        return "Bluetooth Tracker"
    if any(k in low for k in TRACKER_NAME_HINTS):
        return "Bluetooth Tracker"
    if any(k in low for k in ("airpods", "buds", "headphone", "headset", "wh-", "wf-")):
        return "Headphones"
    if any(k in low for k in ("watch", "band", "fit", "amazfit")):
        return "Wearable"
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


class BluetoothBackend(DiscoveryBackend):
    name = "ble"
    requires = ("bleak",)

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

            name = adv.local_name or ble_device.name
            device_type = classify_ble(
                name, vendor, adv.manufacturer_data, adv.service_uuids, dtype
            )

            devices.append(
                DiscoveredDevice(
                    source="ble",
                    mac=address,
                    name=name,
                    vendor=vendor,
                    device_type=device_type,
                    services=services or ["BLE"],
                    attributes={
                        "bluetooth": True,
                        "rssi": adv.rssi,
                        "tx_power": adv.tx_power,
                        "service_uuids": list(adv.service_uuids or []),
                        "manufacturer_ids": [hex(c) for c in (adv.manufacturer_data or {})],
                    },
                )
            )
        return devices


def discover(timeout: float = 8.0) -> list[DiscoveredDevice]:
    return BluetoothBackend().safe_discover(timeout=timeout)


def demo():
    # AirTag separated from owner: Apple Find My offline-finding payload.
    assert classify_ble("Müezza", "Apple", {0x004C: b"\x12\x19\x00"}, [], None) == "Bluetooth Tracker"
    # Galaxy SmartTag via SmartThings Find service UUID.
    assert classify_ble("Tag", "Samsung", {}, ["0000fd5a-0000-1000-8000-00805f9b34fb"], None) == "Bluetooth Tracker"
    # A plain Apple beacon is not a tracker.
    assert classify_ble("iPhone", "Apple", {0x004C: b"\x10\x05"}, [], None) == "Bluetooth Device"
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
