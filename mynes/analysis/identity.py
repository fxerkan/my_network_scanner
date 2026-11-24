"""Device identity: one place that turns every signal into a name and a type.

Why this exists. MyNeS collected plenty of evidence - the OUI vendor, open
ports, banners, mDNS, SSDP, ONVIF - but each consumer read a different subset
and the last writer won. On a real home LAN that produced a Samsung TV typed as
a "Samsung Smartphone" (Samsung OUI, every port filtered in standby), a Tapo
bulb typed as a "Router" (TP-Link OUI), a Petkit litter box called "Espressif
IoT Device" and a MacBook typed "Media Player" (it advertises AirPlay).

The fix is two rules:

1. **Self-reported evidence beats inference.** A device that tells us its own
   hostname over DHCP ("Petkit_T4", "L510", "C200C"), its model over mDNS
   ("MacBookPro18,3") or its name over a vendor protocol (a Philips purifier
   answers CoAP with ``{"name": "Mutfak", "modelid": "AMF870/15"}``) outranks
   anything we can guess from an OUI.
2. **The best identification sticks.** A TV that answered on its cast ports
   once stays a TV when the next scan finds it asleep. ``identity`` on the
   device records the strongest verdict seen; a weaker one never replaces it.
   A user edit (``user_modified``) always wins over both.

Everything here is pure: ``identify(device, evidence)`` and
``apply_identity(device, ident)`` do no I/O, so they are tested directly.
The probes that *collect* evidence live in ``analysis/probes.py``.
"""

from __future__ import annotations

import re
from datetime import datetime

# ---------------------------------------------------------------------------
# Vendor clean-up
# ---------------------------------------------------------------------------

# OUI registrations under a holding/trading company name nobody recognises.
VENDOR_ALIASES = (
    (re.compile(r"fantasia trading", re.I), "Anker Innovations"),
    (re.compile(r"shanghai mxchip", re.I), "MXCHIP (Wi-Fi module)"),
    (re.compile(r"azurewave", re.I), "AzureWave (Wi-Fi module)"),
    (re.compile(r"sichuan ai-link", re.I), "AI-Link (Wi-Fi module)"),
    (re.compile(r"^espressif", re.I), "Espressif (Wi-Fi module)"),
)

# Module makers: the OUI names the radio, not the product it is inside.
MODULE_VENDORS = re.compile(r"espressif|mxchip|azurewave|ai-link|realtek|tuya|hui zhou gaoshengda|"
                            r"telink|beken|bouffalo|winner micro|lexin", re.I)


def display_vendor(vendor: str | None) -> str | None:
    for pattern, alias in VENDOR_ALIASES:
        if vendor and pattern.search(vendor):
            return alias
    return vendor


# ---------------------------------------------------------------------------
# Apple model identifiers (mDNS device-info / _companion-link TXT "model=")
# ---------------------------------------------------------------------------

APPLE_MODELS = (
    (re.compile(r"^macbook", re.I), "Laptop"),
    (re.compile(r"^(imac|macmini|macpro|mac\d+,\d+|macstudio)", re.I), "Desktop"),
    (re.compile(r"^ipad", re.I), "Tablet"),
    (re.compile(r"^iphone", re.I), "Smartphone"),
    (re.compile(r"^watch", re.I), "Smart Watch"),
    (re.compile(r"^(appletv|audioaccessory)", re.I), "Streaming Device"),
)


def apple_type(model: str | None) -> str | None:
    for pattern, dtype in APPLE_MODELS:
        if model and pattern.search(model):
            return dtype
    return None


# ---------------------------------------------------------------------------
# Signatures - ordered, first strong match per field wins
# ---------------------------------------------------------------------------
# Each signature: conditions (all must hold) -> type / vendor / name template.
#   oui       regex on the OUI vendor        vendor   display vendor to set
#   host      regex on any self-reported hostname (DHCP, mDNS, NetBIOS, rDNS)
#   ports     set: all must be open        ports_any: at least one open
#   probe     key that must be present in evidence["probes"]
#   service   regex on any mDNS/SSDP service name
# The name template may use {host}, {model}, {probe_name}.

SIGNATURES = [
    # -- vendor protocols that name the device outright -------------------
    {"probe": "philips_coap", "type": "Air Purifier", "vendor": "Philips", "conf": 0.97,
     "name": "Philips {model} - {probe_name}", "why": "Philips CoAP /sys/dev/info"},
    {"probe": "airstage", "type": "Air Conditioner", "vendor": "Fujitsu General (AirStage)", "conf": 0.95,
     "name": "Fujitsu AirStage AC", "why": "Fujitsu AirStage /GetParam API"},

    {"probe": "tplink_easy_smart", "type": "Switch", "vendor": "TP-Link", "conf": 0.93,
     "name": "TP-Link Easy Smart Switch {model}", "why": "TP-Link Easy Smart switch web UI"},
    {"oui": r"dyson", "ports_any": {1883}, "type": "Air Purifier", "vendor": "Dyson", "conf": 0.85,
     "name": "Dyson Purifier", "why": "Dyson local MQTT (purifier/fan)"},
    {"oui": r"dyson", "type": "Air Purifier", "vendor": "Dyson", "conf": 0.72, "name": "Dyson Purifier",
     "why": "Dyson OUI"},
    {"oui": r"raspberry pi", "type": "Single Board Computer", "vendor": "Raspberry Pi", "conf": 0.86,
     "name": None, "why": "Raspberry Pi OUI"},
    {"vclass": r"^android-dhcp", "type": "Smartphone", "conf": 0.8, "name": None,
     "why": "Android DHCP vendor class"},
    {"vclass": r"^msft", "type": "Desktop", "conf": 0.7, "name": None, "why": "Windows DHCP vendor class"},

    # -- self-reported hostnames ------------------------------------------
    {"host": r"^petkit[_-]?t\d", "type": "Pet Litter Box", "vendor": "Petkit", "conf": 0.93,
     "name": "Petkit Litter Box ({host})", "why": "Petkit T-series hostname"},
    {"host": r"^petkit[_-]?d\d", "type": "Pet Feeder", "vendor": "Petkit", "conf": 0.93,
     "name": "Petkit Feeder ({host})", "why": "Petkit D-series hostname"},
    {"host": r"^petkit[_-]?c?tw\d|^petkit[_-]?w\d", "type": "Pet Water Fountain", "vendor": "Petkit", "conf": 0.93,
     "name": "Petkit Water Fountain ({host})", "why": "Petkit fountain name"},
    {"oui": r"tp-?link", "host": r"^(l5\d\d|l6\d\d|l9\d\d|l530|kl\d{3})", "type": "Smart Light", "vendor": "TP-Link Tapo",
     "conf": 0.92, "name": "Tapo {host} Bulb", "why": "Tapo bulb model as hostname"},
    {"oui": r"tp-?link", "host": r"^(p1\d\d|p3\d\d|hs1\d\d|kp\d{3})", "type": "Smart Plug", "vendor": "TP-Link Tapo",
     "conf": 0.92, "name": "Tapo {host} Plug", "why": "Tapo plug model as hostname"},
    {"oui": r"tp-?link", "host": r"^c\d{3}[a-z]?$|^tc\d{2}", "type": "IP Camera", "vendor": "TP-Link Tapo",
     "conf": 0.92, "name": "Tapo {host} Camera", "why": "Tapo camera model as hostname"},
    {"host": r"^deco", "type": "Access Point", "conf": 0.9, "name": "{host}", "why": "Deco mesh hostname"},
    {"host": r"pixel|galaxy|^sm-[a-z]\d|oneplus|redmi|^android-[0-9a-f]{8,}", "type": "Smartphone", "conf": 0.88,
     "name": "{host}", "why": "phone hostname"},
    {"host": r"iphone|iphon", "type": "Smartphone", "vendor": "Apple", "conf": 0.9, "name": "{host}",
     "why": "iPhone hostname"},
    {"host": r"ipad", "type": "Tablet", "vendor": "Apple", "conf": 0.9, "name": "{host}", "why": "iPad hostname"},
    {"host": r"macbook|mbp|-mba\b|macbookair|macbookpro", "type": "Laptop", "vendor": "Apple", "conf": 0.88,
     "name": "{host}", "why": "MacBook hostname"},
    {"host": r"^roborock|rockrobo", "type": "Vacuum Cleaner", "conf": 0.9, "name": "Roborock {host}",
     "why": "Roborock hostname"},
    {"oui": r"azurewave", "host": r"^device_[0-9a-f]{4}$", "type": "Air Conditioner", "conf": 0.8,
     "name": "AC Wi-Fi Adapter ({host})", "why": "AirStage adapter default hostname"},

    # -- service / port shapes -------------------------------------------
    {"service": r"google ?cast|android tv", "type": "Smart TV", "conf": 0.9, "name": None, "why": "Google Cast / Android TV"},
    {"oui": r"samsung", "ports_any": {8001, 8002, 9197, 7676, 9110}, "type": "Smart TV", "vendor": "Samsung",
     "conf": 0.9, "name": "Samsung Smart TV", "why": "Samsung TV control/DLNA port"},
    {"service": r"samsung.*(tv|remotecontrol)|dial", "oui": r"samsung", "type": "Smart TV", "vendor": "Samsung", "conf": 0.9,
     "name": "Samsung Smart TV", "why": "Samsung TV SSDP"},
    {"ports": {6668, 554}, "type": "IP Camera", "vendor": "Tuya", "conf": 0.85,
     "name": "Tuya Camera Device", "why": "Tuya local protocol + RTSP (camera, video doorbell or camera feeder)"},
    {"ports_any": {6668}, "type": "Smart Home", "vendor": "Tuya", "conf": 0.8,
     "name": "Tuya Smart Device", "why": "Tuya local protocol (6668)"},
    {"oui": r"fantasia trading|anker", "type": "Smart Home", "vendor": "Anker Innovations", "conf": 0.6,
     "name": "Anker Device", "why": "Anker OUI (Solix power station / eufy)"},
    {"oui": r"telink", "type": "Bluetooth Device", "conf": 0.5, "name": None, "why": "Telink BLE module"},
]

_COMPILED = []
for _sig in SIGNATURES:
    _c = dict(_sig)
    for _k in ("oui", "host", "service", "vclass"):
        if _k in _c:
            _c[_k + "_re"] = re.compile(_c[_k], re.I)
    _COMPILED.append(_c)


# TP-Link UDP 20002 discovery device_type -> MyNeS type
TPLINK_TYPES = {
    "SMART.TAPOBULB": "Smart Light", "SMART.KASABULB": "Smart Light", "SMART.TAPOLIGHTSTRIP": "Smart Light",
    "SMART.TAPOPLUG": "Smart Plug", "SMART.KASAPLUG": "Smart Plug", "SMART.TAPOSWITCH": "Smart Plug",
    "SMART.KASASWITCH": "Smart Plug", "SMART.IPCAMERA": "IP Camera", "SMART.TAPOHUB": "Smart Home",
    "SMART.TAPOROBOVAC": "Vacuum Cleaner", "HOMEWIFISYSTEM": "Access Point",
}


def _tplink_identity(probe: dict):
    dtype = TPLINK_TYPES.get(str(probe.get("device_type") or "").upper())
    if not dtype:
        return None
    model = re.sub(r"\(.*?\)", "", probe.get("model") or "").strip()
    if dtype == "Access Point":
        role = probe.get("role")
        name = f"Deco {model}" + (f" ({role})" if role else "")
        return dtype, "TP-Link Deco", name.strip(), model
    return dtype, "TP-Link Tapo", f"Tapo {model}".strip(), model


def _clean_host(name: str | None) -> str:
    if not name:
        return ""
    name = re.sub(r"\.(local|lan|home|localdomain)\.?$", "", str(name).strip(), flags=re.I)
    return "" if re.fullmatch(r"[0-9.:a-f-]{7,}", name, re.I) else name


def _hosts(evidence: dict) -> list[str]:
    seen, out = set(), []
    for h in (evidence.get("dhcp_hostname"), evidence.get("mdns_hostname"),
              evidence.get("netbios_name"), evidence.get("hostname")):
        h = _clean_host(h)
        if h and h.lower() not in seen:
            seen.add(h.lower())
            out.append(h)
    return out


def _fmt(template, host, evidence):
    probe = next(iter((evidence.get("probes") or {}).values()), {}) or {}
    values = {"host": host or "", "model": evidence.get("model") or probe.get("model") or "",
              "probe_name": probe.get("name") or ""}
    text = template.format(**values)
    text = re.sub(r"\s*\(\s*\)|\s+-\s*$|^\s*-\s+", "", text).strip()
    return re.sub(r"\s{2,}", " ", text) or None


def identify(device: dict, evidence: dict) -> dict:
    """Pure: everything known about one device -> its best identity.

    ``evidence`` keys (all optional): vendor, open_ports, dhcp_hostname,
    dhcp_vendor_class, mdns_hostname, mdns_model, mdns_name, services,
    ssdp_name, ssdp_model, onvif_name, netbios_name, hostname,
    probes ({"philips_coap": {...}, "airstage": {...}}), fingerprint
    ({device_type, confidence, reasons}).
    Returns {device_type, confidence, name, vendor, model, hostname, reasons}.
    """
    vendor = evidence.get("vendor") or device.get("vendor") or ""
    ports = {int(p["port"] if isinstance(p, dict) else p)
             for p in (evidence.get("open_ports") or device.get("open_ports") or [])
             if str(p["port"] if isinstance(p, dict) else p).isdigit()}
    hosts = _hosts(evidence)
    services = " | ".join(evidence.get("services") or [])
    probes = evidence.get("probes") or {}
    best = {"device_type": None, "confidence": 0.0, "name": None, "vendor": None,
            "model": evidence.get("model") or evidence.get("mdns_model") or evidence.get("ssdp_model"),
            "hostname": hosts[0] if hosts else None, "reasons": []}

    fp = evidence.get("fingerprint") or {}
    if fp.get("device_type") and fp.get("device_type") != "Unknown":
        best.update(device_type=fp["device_type"], confidence=float(fp.get("confidence") or 0))
        best["reasons"] += list(fp.get("reasons") or [])

    # Apple's own model identifier is as good as it gets.
    at = apple_type(best["model"])
    if at and best["confidence"] < 0.95:
        best.update(device_type=at, confidence=0.95, vendor="Apple")
        best["reasons"].append(f"Apple model {best['model']}")

    tp = probes.get("tplink")
    if tp:
        hit = _tplink_identity(tp)
        if hit and 0.96 > best["confidence"]:
            best.update(device_type=hit[0], confidence=0.96, vendor=hit[1], name=hit[2], model=hit[3] or best["model"])
            best["reasons"].append(f"TP-Link discovery: {tp.get('device_type')} {tp.get('model') or ''}".strip())

    vclass = evidence.get("dhcp_vendor_class") or ""
    for sig in _COMPILED:
        if "vclass_re" in sig and not sig["vclass_re"].search(vclass):
            continue
        if "probe" in sig and sig["probe"] not in probes:
            continue
        if "oui_re" in sig and not sig["oui_re"].search(vendor):
            continue
        host = None
        if "host_re" in sig:
            host = next((h for h in hosts if sig["host_re"].search(h)), None)
            if not host:
                continue
        if "service_re" in sig and not sig["service_re"].search(services):
            continue
        if "ports" in sig and not sig["ports"] <= ports:
            continue
        if "ports_any" in sig and not (sig["ports_any"] & ports):
            continue
        if sig.get("probe"):
            best["model"] = (probes[sig["probe"]] or {}).get("model") or best["model"]
        if sig["conf"] > best["confidence"]:
            best["device_type"] = sig["type"]
            best["confidence"] = sig["conf"]
            best["vendor"] = sig.get("vendor") or best["vendor"]
            best["reasons"].append(sig["why"])
        elif not best["vendor"] and sig.get("vendor"):
            best["vendor"] = sig["vendor"]
        # A matching signature names the device even when a louder signal
        # (an RTSP answer, say) already settled the type.
        if sig.get("name") and not best["name"]:
            best["name"] = _fmt(sig["name"], host or (hosts[0] if hosts else ""), {**evidence, "model": best["model"]})

    # Names the device (or its owner) chose, in order of trust.
    for candidate in (evidence.get("onvif_name"), evidence.get("ssdp_name"), evidence.get("mdns_name")):
        candidate = _clean_host(candidate)
        if candidate and not best["name"]:
            best["name"] = candidate
    if not best["name"] and hosts and not re.fullmatch(r"(android_|esp[_-]|espressif|mxchip|device_)\w*", hosts[0], re.I):
        best["name"] = hosts[0]

    if not best["vendor"] and vendor and (MODULE_VENDORS.search(vendor) or re.search(r"fantasia", vendor, re.I)):
        best["vendor"] = display_vendor(vendor)
    if not best["device_type"]:
        best["device_type"], best["confidence"] = "Unknown", 0.0
    return best


# Aliases MyNeS itself generated - safe to replace with a better name.
_PLACEHOLDER = re.compile(
    r"^(unknown|bilinmeyen|)$|"
    r"\b(iot device|smart home|device \d+|smartphone|router|ip camera|air conditioner)$|"
    r"^[0-9a-f:.-]{7,}$|"
    r"^.+ \d{1,3}$",          # "<Vendor> 112" - vendor plus last octet
    re.I)


def is_placeholder_alias(alias: str | None, vendor: str | None = None) -> bool:
    a = (alias or "").strip()
    if not a or _PLACEHOLDER.search(a):
        return True
    v = (vendor or "").split()[0].lower() if vendor else ""
    return bool(v) and a.lower().startswith(v) and len(a.split()) <= 4


def apply_identity(device: dict, ident: dict, now: str | None = None) -> list:
    """Fold an identity into a device record. Pure apart from mutating ``device``.

    - user_modified fields are never touched;
    - device_type changes only when this identity is at least as strong as
      the best one recorded (``device['identity']``) - so a sleeping TV does
      not become a smartphone again;
    - alias is replaced only when it is a MyNeS placeholder or a name an
      earlier identity pass set (alias_source == "identity");
    - hostname is filled when empty; vendor is replaced only when it is a
      module/holding-company OUI name.
    Returns [(field, old, new)] for logging.
    """
    now = now or datetime.now().isoformat()
    user = device.get("user_modified") or {}
    prev = device.get("identity") or {}
    changes = []

    def put(field, value):
        if value in (None, "") or field in user or device.get(field) == value:
            return
        changes.append((field, device.get(field), value))
        device[field] = value

    stronger = ident["confidence"] >= float(prev.get("confidence") or 0) - 1e-9
    if stronger and ident.get("device_type") and ident["device_type"] != "Unknown":
        record = {"device_type": ident["device_type"], "confidence": round(ident["confidence"], 3),
                  "reasons": ident.get("reasons", [])[-4:], "at": now}
        for k in ("name", "model", "vendor", "hostname"):
            if ident.get(k):
                record[k] = ident[k]
        device["identity"] = record
    best = device.get("identity") or {}

    if device.get("device_type_source") != "user" and best.get("device_type"):
        put("device_type", best["device_type"])
        if "device_type" not in user:
            device["device_type_source"] = "auto"
    if best.get("model"):
        put("model", best["model"])
    if not device.get("hostname"):
        put("hostname", ident.get("hostname") or best.get("hostname"))
    vendor = device.get("vendor") or ""
    if best.get("vendor") and (not vendor or vendor in ("Unknown", "Bilinmeyen")
                               or MODULE_VENDORS.search(vendor) or re.search(r"fantasia|ieee registration", vendor, re.I)):
        put("vendor", best["vendor"])
    name = ident.get("name") or best.get("name")
    if name and device.get("alias_source") != "user" and "alias" not in user and (
            device.get("alias_source") == "identity" or is_placeholder_alias(device.get("alias"), vendor)):
        if device.get("alias") != name:
            put("alias", name)
            device["alias_source"] = "identity"
    return changes


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------

def demo():
    # Petkit litter box: Espressif OUI, DHCP hostname Petkit_T4.
    d = {"ip": "192.168.1.109", "mac": "c0:5d:89:cb:6b:1c", "vendor": "Espressif Inc.",
         "alias": "Espressif IoT Device", "device_type": "IoT Device"}
    i = identify(d, {"vendor": d["vendor"], "dhcp_hostname": "Petkit_T4",
                     "fingerprint": {"device_type": "IoT Device", "confidence": 0.65}})
    assert i["device_type"] == "Pet Litter Box" and i["vendor"] == "Petkit", i
    apply_identity(d, i)
    assert d["alias"] == "Petkit Litter Box (Petkit_T4)" and d["device_type"] == "Pet Litter Box", d
    assert d["vendor"] == "Petkit"

    # Tapo bulb: TP-Link OUI must not make it a router.
    i = identify({}, {"vendor": "TP-Link Systems Inc", "dhcp_hostname": "L510",
                      "fingerprint": {"device_type": "Router", "confidence": 0.55}})
    assert i["device_type"] == "Smart Light" and i["name"] == "Tapo L510 Bulb", i

    # Philips purifier names itself over CoAP.
    i = identify({}, {"vendor": "Shanghai MXCHIP Information Technology Co., Ltd.", "dhcp_hostname": "mxchip",
                      "probes": {"philips_coap": {"name": "Mutfak", "model": "AMF870/15"}}})
    assert i["device_type"] == "Air Purifier" and i["name"] == "Philips AMF870/15 - Mutfak", i

    # MacBook advertising AirPlay is a laptop, not a media player.
    i = identify({}, {"vendor": "Unknown", "mdns_hostname": "kafein-mbp-erkan.local", "mdns_model": "MacBookPro18,3",
                      "fingerprint": {"device_type": "Media Player", "confidence": 0.6}})
    assert i["device_type"] == "Laptop" and i["name"] == "kafein-mbp-erkan", i

    # Samsung TV: once seen on its TV port, a sleeping scan cannot demote it.
    tv = {"ip": "192.168.1.155", "vendor": "Samsung Electronics Co.,Ltd", "alias": "Samsung Smartphone"}
    apply_identity(tv, identify(tv, {"vendor": tv["vendor"], "open_ports": [9197, 8001],
                                     "fingerprint": {"device_type": "Smart TV", "confidence": 0.78}}))
    assert tv["device_type"] == "Smart TV" and tv["alias"] == "Samsung Smart TV", tv
    apply_identity(tv, identify(tv, {"vendor": tv["vendor"], "open_ports": [],
                                     "fingerprint": {"device_type": "Smartphone", "confidence": 0.6}}))
    assert tv["device_type"] == "Smart TV", tv

    # A user edit always wins.
    u = {"alias": "Benim Cihazım", "device_type": "Server", "device_type_source": "user",
         "user_modified": {"alias": "Benim Cihazım", "device_type": "Server"}, "vendor": "Espressif Inc."}
    apply_identity(u, identify(u, {"vendor": u["vendor"], "dhcp_hostname": "Petkit_T4"}))
    assert u["alias"] == "Benim Cihazım" and u["device_type"] == "Server", u

    # Tuya camera feeder (6668 + RTSP), Anker OUI, AirStage probe.
    assert identify({}, {"open_ports": [23, 554, 6668]})["device_type"] == "IP Camera"
    assert identify({}, {"vendor": "Fantasia Trading LLC"})["vendor"] == "Anker Innovations"
    assert identify({}, {"vendor": "AzureWave", "probes": {"airstage": {}}})["device_type"] == "Air Conditioner"
    i = identify({}, {"vendor": "TP-Link Systems Inc", "fingerprint": {"device_type": "Router", "confidence": 0.55},
                      "probes": {"tplink": {"device_type": "SMART.TAPOBULB", "model": "L510E(EU)"}}})
    assert i["device_type"] == "Smart Light" and i["name"] == "Tapo L510E", i
    i = identify({}, {"vendor": "TP-Link", "probes": {"tplink": {"device_type": "HOMEWIFISYSTEM", "model": "X50", "role": "master"}}})
    assert i["device_type"] == "Access Point" and i["name"] == "Deco X50 (master)", i
    i = identify({}, {"vendor": "TP-Link", "probes": {"tplink_easy_smart": {"model": None}}})
    assert i["device_type"] == "Switch" and i["name"] == "TP-Link Easy Smart Switch", i
    assert identify({}, {"vendor": "Dyson Limited", "open_ports": [1883],
                         "fingerprint": {"device_type": "Server", "confidence": 0.75}})["device_type"] == "Air Purifier"
    assert identify({}, {"vendor": "Google, Inc.", "dhcp_vendor_class": "android-dhcp-16"})["device_type"] == "Smartphone"
    rt = identify({}, {"open_ports": [23, 554, 6668], "fingerprint": {"device_type": "IP Camera", "confidence": 0.97}})
    assert rt["device_type"] == "IP Camera" and rt["name"] == "Tuya Camera Device" and rt["vendor"] == "Tuya", rt
    assert is_placeholder_alias("Fantasia 112") and is_placeholder_alias("Espressif IoT Device", "Espressif Inc.")
    assert not is_placeholder_alias("Mutfak Temizleyici")
    print("identity: OK")
    return True


if __name__ == "__main__":
    demo()
