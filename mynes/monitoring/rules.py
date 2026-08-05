"""Turn two consecutive scan snapshots into alerts.

Pure functions over plain dicts - no I/O, no scanner, no Flask - so the rules
can be unit-tested without a network. `evaluate()` is the only entry point.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

SEVERITIES = ("info", "warning", "critical")

# Rule ids, so the UI and the config can enable/disable them by name.
NEW_DEVICE = "new_device"
DEVICE_OFFLINE = "device_offline"
DEVICE_ONLINE = "device_online"
IP_CHANGED = "ip_changed"
MAC_CHANGED = "mac_changed"
NEW_PORT = "new_port"
PORT_CLOSED = "port_closed"
HIGH_LATENCY = "high_latency"
LOW_BATTERY = "low_battery"
LOW_VOLTAGE = "low_voltage"
WEAK_SIGNAL = "weak_signal"

DEFAULT_THRESHOLDS = {
    "offline_scans": 2,  # consecutive misses before we call it offline
    "latency_ms": 500,
    "battery_percent": 20,
    "voltage_min": 4.7,  # Raspberry Pi under-voltage territory (5V rail)
    "rssi_dbm": -85,
    "sensitive_ports": [22, 23, 445, 3389, 5900],
}


@dataclass
class Alert:
    rule: str
    severity: str
    title: str
    message: str
    device_id: str | None = None
    device_name: str | None = None
    ip: str | None = None
    mac: str | None = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def is_muted(alert: dict, muted: list[dict] | None) -> bool:
    """Should this alert stay out of the notification channels?

    A mute entry is matched on device_id, mac or ip - whichever the user picked
    in the UI - because the same device is keyed by MAC on one scan and by IP on
    the next when the ARP cache is all we got. `rules` narrows the mute to
    specific rule names; omit it to silence the device outright.
    """
    if not muted:
        return False
    keys = {str(alert.get(k)).lower() for k in ("device_id", "mac", "ip") if alert.get(k)}
    for entry in muted:
        target = str(entry.get("id") or "").lower()
        if not target or target not in keys:
            continue
        only = entry.get("rules")
        if not only or alert.get("rule") in only:
            return True
    return False


def _identity(device: dict) -> str:
    return (device.get("mac") or device.get("ip") or device.get("id") or "").lower()


# A real MAC: six hex octets. Anything else used as an identity - notably the
# rotating CoreBluetooth UUIDs macOS hands out instead of BLE addresses - is
# ephemeral by design and would otherwise be "a new device" on every scan.
_MAC_SHAPED = re.compile(r"^(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}$")


def _has_stable_identity(device: dict) -> bool:
    mac = (device.get("mac") or "").lower()
    if mac:
        return bool(_MAC_SHAPED.match(mac))
    return bool(device.get("ip"))


def _label(device: dict) -> str:
    return device.get("alias") or device.get("hostname") or device.get("name") or device.get("ip") or "unknown"


def _is_online(device: dict) -> bool:
    status = str(device.get("status", "")).lower()
    if status:
        return status in ("online", "up", "active", "1", "true")
    return bool(device.get("is_online", False))


def _ports(device: dict) -> set[int]:
    out = set()
    for p in device.get("open_ports") or device.get("ports") or []:
        if isinstance(p, dict):
            p = p.get("port")
        try:
            out.add(int(p))
        except (TypeError, ValueError):
            continue
    return out


def _number(device: dict, *keys) -> float | None:
    """First numeric value found under `keys`, searching top level then attributes."""
    for container in (device, device.get("attributes") or {}, device.get("telemetry") or {}):
        for key in keys:
            val = container.get(key)
            if val is None:
                continue
            try:
                return float(str(val).rstrip("%vV "))
            except (TypeError, ValueError):
                continue
    return None


def evaluate(
    previous: dict[str, dict],
    current: dict[str, dict],
    miss_counts: dict[str, int] | None = None,
    thresholds: dict | None = None,
    enabled_rules: list[str] | None = None,
) -> tuple[list[Alert], dict[str, int]]:
    """Compare two snapshots keyed by device identity.

    `miss_counts` carries how many consecutive scans each device has been absent,
    so a single dropped ARP reply does not page the user. Returns the alerts plus
    the updated miss counts, which the caller persists for the next round.
    """
    th = {**DEFAULT_THRESHOLDS, **(thresholds or {})}
    misses = dict(miss_counts or {})
    alerts: list[Alert] = []

    # First run: there is no baseline, so *every* device looks new. Record the
    # snapshot silently instead of reporting the whole network as arrivals.
    if not previous:
        return [], misses

    def emit(rule, severity, title, message, device, **details):
        if enabled_rules is not None and rule not in enabled_rules:
            return
        alerts.append(
            Alert(
                rule=rule,
                severity=severity,
                title=title,
                message=message,
                device_id=_identity(device),
                device_name=_label(device),
                ip=device.get("ip"),
                mac=device.get("mac"),
                details=details,
            )
        )

    for key, dev in current.items():
        name = _label(dev)
        old = previous.get(key)
        online = _is_online(dev)

        if online:
            misses.pop(key, None)

        if old is None:
            # A rotating BLE address is "new" every single scan; alerting on it
            # is noise that buries the one arrival that actually matters.
            if _has_stable_identity(dev):
                emit(
                    NEW_DEVICE,
                    "warning",
                    f"New device: {name}",
                    f"{name} ({dev.get('ip') or dev.get('mac')}) appeared on the network for the first time.",
                    dev,
                    vendor=dev.get("vendor"),
                    device_type=dev.get("device_type"),
                )
        else:
            was_online = _is_online(old)
            if online and not was_online:
                emit(DEVICE_ONLINE, "info", f"Back online: {name}", f"{name} is reachable again.", dev)

            if old.get("ip") and dev.get("ip") and old["ip"] != dev["ip"]:
                emit(
                    IP_CHANGED,
                    "info",
                    f"IP changed: {name}",
                    f"{name} moved from {old['ip']} to {dev['ip']}.",
                    dev,
                    old_ip=old["ip"],
                    new_ip=dev["ip"],
                )

            new_ports = _ports(dev) - _ports(old)
            sensitive = new_ports & set(th["sensitive_ports"])
            if new_ports:
                emit(
                    NEW_PORT,
                    "critical" if sensitive else "warning",
                    f"New open port on {name}",
                    f"{name} started listening on {', '.join(map(str, sorted(new_ports)))}.",
                    dev,
                    ports=sorted(new_ports),
                    sensitive=sorted(sensitive),
                )
            closed = _ports(old) - _ports(dev)
            if closed:
                emit(
                    PORT_CLOSED,
                    "info",
                    f"Port closed on {name}",
                    f"{name} stopped listening on {', '.join(map(str, sorted(closed)))}.",
                    dev,
                    ports=sorted(closed),
                )

        if not online:
            continue

        latency = _number(dev, "response_time", "latency", "ping_ms", "rtt")
        if latency is not None and latency > th["latency_ms"]:
            emit(
                HIGH_LATENCY,
                "warning",
                f"High latency: {name}",
                f"{name} responded in {latency:.0f} ms (threshold {th['latency_ms']} ms).",
                dev,
                latency_ms=latency,
            )

        battery = _number(dev, "battery", "battery_percent", "battery_level")
        if battery is not None and battery <= th["battery_percent"]:
            emit(
                LOW_BATTERY,
                "warning" if battery > 5 else "critical",
                f"Low battery: {name}",
                f"{name} battery at {battery:.0f}%.",
                dev,
                battery=battery,
            )

        voltage = _number(dev, "voltage", "supply_voltage", "core_voltage")
        if voltage is not None and voltage < th["voltage_min"]:
            emit(
                LOW_VOLTAGE,
                "critical",
                f"Under-voltage: {name}",
                f"{name} supply at {voltage:.2f} V (below {th['voltage_min']} V) - check the power supply/cable.",
                dev,
                voltage=voltage,
            )

        rssi = _number(dev, "rssi", "signal_strength")
        if rssi is not None and rssi < th["rssi_dbm"]:
            emit(
                WEAK_SIGNAL,
                "info",
                f"Weak signal: {name}",
                f"{name} signal at {rssi:.0f} dBm.",
                dev,
                rssi=rssi,
            )

    for key, old in previous.items():
        if key in current and _is_online(current[key]):
            continue
        if not _is_online(old):
            continue  # already known-offline, do not re-alert

        misses[key] = misses.get(key, 0) + 1
        if misses[key] == th["offline_scans"]:
            dev = current.get(key, old)
            name = _label(dev)
            emit(
                DEVICE_OFFLINE,
                "warning",
                f"Device offline: {name}",
                f"{name} ({dev.get('ip') or dev.get('mac')}) has been unreachable for "
                f"{misses[key]} consecutive scans.",
                dev,
                missed_scans=misses[key],
            )

    # MAC takeover: same IP now answered by a different MAC. Checked across the
    # whole snapshot because the identity key itself changes when this happens.
    prev_by_ip = {d["ip"]: d for d in previous.values() if d.get("ip") and d.get("mac")}
    for dev in current.values():
        old = prev_by_ip.get(dev.get("ip"))
        if old and dev.get("mac") and old["mac"].lower() != dev["mac"].lower():
            emit(
                MAC_CHANGED,
                "critical",
                f"MAC address changed on {dev.get('ip')}",
                f"{dev.get('ip')} now answers from {dev['mac']} (was {old['mac']}). "
                "This can be a DHCP reassignment or ARP spoofing.",
                dev,
                old_mac=old["mac"],
                new_mac=dev["mac"],
            )

    return alerts, misses


def demo():
    """Self-check: the rules fire on the cases that matter and stay quiet otherwise.

    MACs are full six-octet addresses on purpose - `_has_stable_identity` now
    rejects anything else, so short placeholders would silently skip NEW_DEVICE.
    """
    PI, NAS, NEW = "aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02", "aa:bb:cc:00:00:03"
    prev = {
        PI: {"mac": PI, "ip": "192.168.1.10", "alias": "Pi", "status": "online", "open_ports": [80]},
        NAS: {"mac": NAS, "ip": "192.168.1.11", "alias": "NAS", "status": "online"},
    }
    cur = {
        PI: {
            "mac": PI, "ip": "192.168.1.99", "alias": "Pi", "status": "online",
            "open_ports": [80, 22], "voltage": 4.5, "response_time": 900,
        },
        NEW: {"mac": NEW, "ip": "192.168.1.12", "alias": "New Thing", "status": "online"},
    }

    alerts, misses = evaluate(prev, cur)
    fired = {a.rule for a in alerts}
    assert NEW_DEVICE in fired, fired
    assert IP_CHANGED in fired, fired
    assert NEW_PORT in fired, fired
    assert LOW_VOLTAGE in fired, fired
    assert HIGH_LATENCY in fired, fired
    assert next(a for a in alerts if a.rule == NEW_PORT).severity == "critical"  # port 22 is sensitive

    # NAS missed once -> silent; missed twice -> alert. No flapping on a single drop.
    assert DEVICE_OFFLINE not in fired, "should not alert on the first miss"
    alerts2, _ = evaluate(prev, cur, miss_counts=misses)
    assert DEVICE_OFFLINE in {a.rule for a in alerts2}, "should alert on the second miss"

    # Identical snapshots must produce nothing.
    assert evaluate(prev, prev)[0] == [], "stable network must be silent"

    # Same IP, different MAC -> critical.
    spoof_mac = "de:ad:be:ef:00:99"
    spoof, _ = evaluate(prev, {spoof_mac: {"mac": spoof_mac, "ip": "192.168.1.10", "status": "online"}})
    assert MAC_CHANGED in {a.rule for a in spoof}

    # A rotating BLE address must not read as an arrival.
    ble = "7DE7F807-A905-9E49-54FD-7CAD1F3E786D"
    quiet, _ = evaluate(prev, {**prev, ble.lower(): {"mac": ble, "status": "online"}})
    assert quiet == [], [a.title for a in quiet]

    # No baseline yet -> record it silently rather than report the whole network.
    assert evaluate({}, cur)[0] == [], "the first run must not alert"

    # Muting silences notifications, and only for what the user picked.
    offline = {"rule": "device_offline", "device_id": "AA:BB:CC:DD:EE:01", "ip": "192.168.1.9"}
    online = {**offline, "rule": "device_online"}
    assert is_muted(offline, None) is False
    assert is_muted(offline, [{"id": "aa:bb:cc:dd:ee:01"}]) is True   # whole device
    assert is_muted(offline, [{"id": "192.168.1.9"}]) is True         # matched by IP
    assert is_muted(offline, [{"id": "aa:bb:cc:dd:ee:01", "rules": ["device_offline"]}]) is True
    assert is_muted(online, [{"id": "aa:bb:cc:dd:ee:01", "rules": ["device_offline"]}]) is False
    assert is_muted(offline, [{"id": "other"}]) is False
    print("rules demo OK")


if __name__ == "__main__":
    demo()
