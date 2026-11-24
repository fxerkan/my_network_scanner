"""Vendor-protocol probes that make a device say what it is.

Each probe is cheap (one UDP or HTTP round trip, short timeout), never
raises, and is only sent where the OUI already points at that vendor - so a
scan does not spray CoAP at every phone on the LAN. Results feed
``analysis/identity.py`` as ``evidence["probes"]``.

- **Philips air purifiers** (CoAP, UDP 5683): ``GET /sys/dev/info`` answers
  without pairing: ``{"name": "Mutfak", "modelid": "AMF870/15", ...}``. The
  name is the one the owner gave it in the Philips app.
- **Fujitsu AirStage** Wi-Fi adapters (HTTP 80): ``POST /GetParam`` answers
  with a JSON ``{"result": ...}`` envelope even without a valid device id -
  a shape nothing else on a home LAN serves.
"""

from __future__ import annotations

import json
import os
import re
import socket
import urllib.request

PHILIPS_OUI = re.compile(r"mxchip|philips", re.I)
AIRSTAGE_OUI = re.compile(r"azurewave|fujitsu", re.I)


def _coap_get_packet(path: str) -> bytes:
    """Pure: a confirmable CoAP GET with one Uri-Path option per segment."""
    out, last = b"", 0
    for seg in path.strip("/").split("/"):
        delta, last = 11 - last, 11            # option 11 = Uri-Path
        data = seg.encode()
        if len(data) > 12:
            out += bytes([(delta << 4) | 13, len(data) - 13]) + data
        else:
            out += bytes([(delta << 4) | len(data)]) + data
    return bytes([0x40, 0x01]) + os.urandom(2) + out


def _coap_payload(raw: bytes) -> bytes | None:
    """Pure: the payload after the 0xFF marker, or None."""
    i = raw.find(b"\xff")
    return raw[i + 1:] if i >= 0 else None


def philips_coap(ip: str, timeout: float = 1.5) -> dict | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(_coap_get_packet("/sys/dev/info"), (ip, 5683))
            raw, _ = s.recvfrom(4096)
        info = json.loads((_coap_payload(raw) or b"").decode("utf-8", "replace"))
    except (OSError, ValueError):
        return None
    if not isinstance(info, dict) or not (info.get("modelid") or info.get("type")):
        return None
    return {"name": info.get("name"), "model": info.get("modelid") or info.get("type"),
            "device_id": info.get("device_id"), "firmware": info.get("swversion")}


def airstage(ip: str, timeout: float = 2.0) -> dict | None:
    body = json.dumps({"device_id": "", "device_sub_id": 0, "req_id": "", "modified_by": "",
                       "set_level": "03", "list": ["iu_model"]}).encode()
    req = urllib.request.Request(f"http://{ip}/GetParam", data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - LAN probe
            data = json.loads(resp.read(4096).decode("utf-8", "replace"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or "result" not in data:
        return None
    model = ((data.get("value") or {}) if isinstance(data.get("value"), dict) else {}).get("iu_model")
    return {"model": model, "result": data.get("result")}


TPLINK_OUI = re.compile(r"tp-?link", re.I)
# Unauthenticated local discovery that Tapo/Kasa "SMART" devices and Deco
# units answer on UDP 20002 (the same query python-kasa sends): a 16-byte
# header followed by plain JSON naming device_type and device_model.
_TPLINK_QUERY = bytes.fromhex("020000010000000000000000463cb5d3")


def _tplink_parse(raw: bytes) -> dict | None:
    """Pure: the 20002 answer -> {device_type, model, role} or None."""
    try:
        data = json.loads(raw[16:].decode("utf-8", "replace"))
    except ValueError:
        return None
    res = data.get("result") if isinstance(data, dict) else None
    if not isinstance(res, dict) or not res.get("device_type"):
        return None
    return {"device_type": res.get("device_type"), "model": res.get("device_model"),
            "role": res.get("role")}


def tplink_discovery(ip: str, timeout: float = 1.5) -> dict | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(_TPLINK_QUERY, (ip, 20002))
            raw, _ = s.recvfrom(8192)
    except OSError:
        return None
    return _tplink_parse(raw)


def tplink_easy_smart(ip: str, timeout: float = 2.0) -> dict | None:
    """TP-Link Easy Smart switches (TL-SG105E/108E/105PE/1016DE...) serve a
    login page built around a ``logonInfo`` array - nothing else does."""
    try:
        with urllib.request.urlopen(f"http://{ip}/", timeout=timeout) as resp:  # noqa: S310
            body = resp.read(65536).decode("utf-8", "replace")
    except (OSError, ValueError):
        return None
    if "logonInfo" in body and "account_restored" in body:
        m = re.search(r"TL-S[GL]\d{3,4}[A-Z]*", body)
        return {"model": m.group(0) if m else None}
    return None


def run_for(ip: str, vendor: str | None, open_ports=None) -> dict:
    """Run every probe this device's vendor makes plausible. -> {probe: result}."""
    vendor = vendor or ""
    found = {}
    if PHILIPS_OUI.search(vendor):
        r = philips_coap(ip)
        if r:
            found["philips_coap"] = r
    if AIRSTAGE_OUI.search(vendor):
        r = airstage(ip)
        if r:
            found["airstage"] = r
    if TPLINK_OUI.search(vendor):
        r = tplink_discovery(ip)
        if r:
            found["tplink"] = r
        else:
            ports = {int(p["port"] if isinstance(p, dict) else p) for p in (open_ports or [])}
            if not ports or 80 in ports:
                r = tplink_easy_smart(ip)
                if r is not None:
                    found["tplink_easy_smart"] = r
    return found


def demo():
    pkt = _coap_get_packet("/sys/dev/info")
    assert pkt[:2] == b"\x40\x01" and pkt[4:] == b"\xb3sys\x03dev\x04info", pkt
    assert _coap_payload(b"\x60\x45\x00\x01\xff{\"a\":1}") == b'{"a":1}'
    assert _coap_payload(b"\x60\x45\x00\x01") is None
    assert run_for("192.0.2.1", "Samsung Electronics") == {}      # no probe for other vendors
    bulb = b"\x02" * 16 + b'{"result":{"device_type":"SMART.TAPOBULB","device_model":"L510E(EU)"},"error_code":0}'
    assert _tplink_parse(bulb) == {"device_type": "SMART.TAPOBULB", "model": "L510E(EU)", "role": None}
    assert _tplink_parse(b"\x00" * 16 + b"nope") is None
    print("probes: OK")
    return True


if __name__ == "__main__":
    demo()
