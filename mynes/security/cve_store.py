"""Official CVE reference database - the CVE Project's CVE List V5 corpus.

This is the *metadata/reference* store, not a scanner. Matching stays curated
(banner regexes in ``cve.py``'s ``CVE_PATTERNS``); what this module holds is the
authoritative title/description/references/CVSS for CVE ids, downloaded from the
official CVE Project release feed and refreshed like the OUI database:

    https://api.github.com/repos/CVEProject/cvelistV5/releases/latest

Two assets on every release:
  * a small DELTA zip (``*_delta_CVEs_at_*.zip``, ~0.1 MB) - the default update.
  * a large FULL zip (``*_all_CVEs_at_midnight.zip.zip``, ~570 MB, NESTED) -
    the optional full import, size-warned in the UI.

250k+ rows make JSON infeasible, so the store is a single stdlib ``sqlite3``
file at ``data_file('cve_records.db')``. A finding from ``cve.py`` is enriched
by id from here when present (official DB > JSON overlay > built-in), and the
whole thing degrades to nothing if the DB is missing or locked.

    python -m mynes.security.cve_store      # self-check
"""

from __future__ import annotations

import io
import os
import re
import sqlite3
import tempfile
import zipfile
from datetime import datetime, timezone

from mynes.paths import data_file

# The official CVE Project release feed (GitHub Releases API). No API key.
CVELIST_V5_LATEST = "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest"
_DB_NAME = "cve_records.db"
_UA = "MyNeS/CVE-list-v5"


def _db_path() -> str:
    return data_file(_DB_NAME)


def _connect() -> sqlite3.Connection:
    """Open the DB and ensure the schema exists. Callers close it."""
    conn = sqlite3.connect(_db_path(), timeout=15)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS cve (
            cve_id      TEXT PRIMARY KEY,
            title       TEXT,
            description TEXT,
            severity    TEXT,
            cvss        REAL,
            refs        TEXT,
            published   TEXT,
            modified    TEXT,
            source      TEXT,
            updated_at  TEXT
        )"""
    )
    return conn


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------
# Network-relevance filter. MyNeS scans a LAN, so a CVE only earns a place in
# the store if it can be reached over the network. The authoritative signal is
# the CVSS Attack Vector: keep Network (AV:N) and Adjacent/LAN (AV:A), drop
# Local (AV:L) and Physical (AV:P) - a local-only library integer overflow is
# not something a network scanner can see. Records with no CVSS fall back to a
# keyword allowlist over the affected products/description so we don't hoard
# the whole 250k-CVE corpus, most of which is desktop/library/local bugs.
# --------------------------------------------------------------------------

_NET_KEYWORDS = re.compile(
    r"\b("
    r"router|gateway|switch|firewall|vpn|nas|camera|ip ?cam|webcam|nvr|dvr|"
    r"iot|printer|scanner|access ?point|wi-?fi|wireless|ethernet|smart ?(home|plug|bulb|lock|tv|speaker)|"
    r"zigbee|z-?wave|matter|homekit|modem|voip|sip|rtsp|onvif|upnp|ssdp|mdns|bonjour|mqtt|coap|"
    r"snmp|smb|samba|cifs|netbios|telnet|ssh|sftp|ftp|tftp|https?|tls|ssl|tcp|udp|dns|dhcp|ldap|kerberos|"
    r"rdp|vnc|rpc|web ?(interface|server|ui|admin|panel|console)|remote code|remote attacker|"
    r"unauthenticated|network|firmware|windows|linux|unix|macos|mac ?os|android|ios|"
    r"synology|qnap|truenas|openwrt|dd-wrt|mikrotik|ubiquiti|unifi|tp-?link|netgear|d-?link|"
    r"hikvision|dahua|reolink|tenda|zyxel|asus|cisco|juniper|fortinet|sonicwall|palo alto|"
    r"home ?assistant|nginx|apache|openssh|openssl|lighttpd|dnsmasq|busybox|proxy"
    r")\b",
    re.I,
)


def _cna(record: dict) -> dict:
    return (record.get("containers") or {}).get("cna") or {}


def _attack_vector(record: dict):
    """The CVSS attack vector letter (N/A/L/P) from any metric block, or None."""
    cna = _cna(record)
    blocks = list(cna.get("metrics") or [])
    for adp in record.get("containers", {}).get("adp") or []:
        blocks += adp.get("metrics") or []
    for m in blocks:
        for key, val in m.items():
            if key.lower().startswith("cvss") and isinstance(val, dict):
                av = val.get("attackVector")
                if isinstance(av, str) and av:
                    return av.upper()[:1]
                mm = re.search(r"AV:([NALP])", val.get("vectorString") or "", re.I)
                if mm:
                    return mm.group(1).upper()
    return None


def _relevance_text(record: dict) -> str:
    cna = _cna(record)
    parts = []
    for d in cna.get("descriptions") or []:
        if d.get("value"):
            parts.append(d["value"])
    if cna.get("title"):
        parts.append(cna["title"])
    for aff in cna.get("affected") or []:
        for k in ("vendor", "product"):
            if aff.get(k):
                parts.append(str(aff[k]))
    return " ".join(parts)


def is_network_relevant(record: dict) -> bool:
    """True if this CVE could plausibly be found/exploited over a LAN."""
    av = _attack_vector(record)
    if av in ("N", "A"):
        return True
    if av in ("L", "P"):
        return False
    return bool(_NET_KEYWORDS.search(_relevance_text(record)))


def _record_row(record: dict, source: str):
    """Flatten one CVE-5.x record to a row tuple, reusing cve.py's _extract_meta.
    Returns None for anything that isn't a usable record - never raises."""
    try:
        from mynes.security.cve import _extract_meta  # local import: avoid cycle
        if not isinstance(record, dict):
            return None
        cve_id = (record.get("cveMetadata") or {}).get("cveId")
        if not isinstance(cve_id, str) or not cve_id.strip():
            return None
        cve_id = cve_id.strip()
        # Only keep CVEs a network scanner could actually surface (see
        # is_network_relevant): drop local-only / desktop-library noise.
        if not is_network_relevant(record):
            return None
        meta = _extract_meta(record)
        cve_meta = record.get("cveMetadata") or {}
        published = cve_meta.get("datePublished")
        modified = cve_meta.get("dateUpdated") or cve_meta.get("dateReserved")
        return (
            cve_id,
            meta.get("title"),
            meta.get("description"),
            meta.get("severity"),
            meta.get("cvss"),
            meta.get("reference"),
            published if isinstance(published, str) else None,
            modified if isinstance(modified, str) else None,
            source,
            _now(),
        )
    except Exception:  # noqa: BLE001 - one bad record must never break the batch
        return None


def upsert_records(records, source: str = "cvelistV5") -> int:
    """INSERT OR REPLACE each CVE-5.x record. Bad records are skipped. Returns
    the number of rows written. Never raises on a bad record; a DB failure
    propagates to the sync caller which itself never raises."""
    conn = _connect()
    written = 0
    try:
        batch = []
        for rec in records:
            row = _record_row(rec, source)
            if row is None:
                continue
            batch.append(row)
            if len(batch) >= 500:
                conn.executemany(
                    "INSERT OR REPLACE INTO cve VALUES (?,?,?,?,?,?,?,?,?,?)", batch
                )
                written += len(batch)
                batch = []
        if batch:
            conn.executemany(
                "INSERT OR REPLACE INTO cve VALUES (?,?,?,?,?,?,?,?,?,?)", batch
            )
            written += len(batch)
        conn.commit()
    finally:
        conn.close()
    return written


_COLS = ("cve_id", "title", "description", "severity", "cvss",
         "refs", "published", "modified", "source", "updated_at")


def get_record(cve_id: str):
    """One authoritative record by id, or None (missing DB/row/error)."""
    if not isinstance(cve_id, str) or not cve_id.strip():
        return None
    if not os.path.exists(_db_path()):
        return None
    try:
        conn = _connect()
        try:
            cur = conn.execute(
                "SELECT " + ",".join(_COLS) + " FROM cve WHERE cve_id = ?",
                (cve_id.strip().upper(),),
            )
            row = cur.fetchone()
        finally:
            conn.close()
    except sqlite3.Error:
        return None
    return dict(zip(_COLS, row)) if row else None


def search(q: str, limit: int = 50) -> list:
    """Match cve_id OR title/description LIKE q, newest first. [] on any error."""
    q = (q or "").strip()
    if not q or not os.path.exists(_db_path()):
        return []
    try:
        limit = max(1, min(int(limit), 200))
    except (TypeError, ValueError):
        limit = 50
    like = f"%{q}%"
    try:
        conn = _connect()
        try:
            cur = conn.execute(
                "SELECT " + ",".join(_COLS) + " FROM cve "
                "WHERE cve_id LIKE ? OR title LIKE ? OR description LIKE ? "
                "ORDER BY COALESCE(published, modified, '') DESC LIMIT ?",
                (like.upper(), like, like, limit),
            )
            rows = cur.fetchall()
        finally:
            conn.close()
    except sqlite3.Error:
        return []
    return [dict(zip(_COLS, r)) for r in rows]


def stats() -> dict:
    """{count, last_updated} for the Settings card. Empty/missing -> zeros."""
    if not os.path.exists(_db_path()):
        return {"count": 0, "last_updated": None}
    try:
        conn = _connect()
        try:
            count = conn.execute("SELECT COUNT(*) FROM cve").fetchone()[0]
            last = conn.execute("SELECT MAX(updated_at) FROM cve").fetchone()[0]
        finally:
            conn.close()
    except sqlite3.Error:
        return {"count": 0, "last_updated": None}
    return {"count": int(count), "last_updated": last}


# ---------------------------------------------------------------------------
# Sync from the official CVE List V5 release feed.
# ---------------------------------------------------------------------------

def _pick_asset(assets: list, mode: str):
    """Choose the delta or full asset from a release's assets by name pattern."""
    for a in assets:
        name = (a.get("name") or "").lower()
        url = a.get("browser_download_url")
        if not url:
            continue
        if mode == "delta" and "_delta_cves_at_" in name and name.endswith(".zip"):
            return a
        # The full asset is doubly-zipped: "*_all_CVEs_at_midnight.zip.zip".
        if mode == "full" and "_all_cves_at_" in name and name.endswith(".zip"):
            return a
    return None


def _iter_cve_jsons_from_zip(zf: zipfile.ZipFile):
    """Yield parsed CVE-5.x records from every CVE-*.json entry in a zip."""
    import json
    for info in zf.infolist():
        name = info.filename
        if not name.endswith(".json"):
            continue
        base = name.rsplit("/", 1)[-1]
        if not base.startswith("CVE-"):
            continue
        try:
            with zf.open(info) as fh:
                yield json.loads(fh.read().decode("utf-8"))
        except Exception:  # noqa: BLE001 - skip a single unreadable entry
            continue


def sync_cve_list_v5(mode: str = "delta") -> dict:
    """Download the latest CVE List V5 release asset (delta or full), unzip it,
    walk every CVE record and upsert into the SQLite store.

    Offline-safe: never raises; returns {ok:False, error:...} on any failure.
    ``full`` streams the ~570 MB nested ``.zip.zip`` to a temp file and deletes
    it after - it is never held in memory."""
    if mode not in ("delta", "full"):
        return {"ok": False, "error": "mode must be 'delta' or 'full'"}
    try:
        import requests
    except ImportError:
        return {"ok": False, "error": "requests not installed"}

    headers = {"User-Agent": _UA, "Accept": "application/vnd.github+json"}
    try:
        rel = requests.get(CVELIST_V5_LATEST, timeout=20, headers=headers)
        rel.raise_for_status()
        assets = (rel.json() or {}).get("assets") or []
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"release lookup failed: {e}"}

    asset = _pick_asset(assets, mode)
    if not asset:
        return {"ok": False, "error": f"no {mode} asset found in latest release"}

    url = asset["browser_download_url"]
    try:
        if mode == "delta":
            written = _sync_delta(url)
        else:
            written = _sync_full(url)
    except Exception as e:  # noqa: BLE001 - download/unzip failures expected offline
        return {"ok": False, "error": str(e)}

    if written == 0:
        return {"ok": False, "error": "no CVE records parsed from the asset"}
    st = stats()
    return {"ok": True, "mode": mode, "written": written,
            "records_count": st["count"], "records_last_updated": st["last_updated"],
            "asset": asset.get("name")}


def _sync_delta(url: str) -> int:
    """Delta zip is tiny (~0.1 MB): download in-memory, walk deltaCves/*.json."""
    import requests
    resp = requests.get(url, timeout=60, headers={"User-Agent": _UA})
    resp.raise_for_status()
    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
        return upsert_records(_iter_cve_jsons_from_zip(zf), source="cvelistV5-delta")


def _sync_full(url: str) -> int:
    """Full zip is a NESTED ~570 MB .zip.zip: stream the outer zip to a temp
    file, open the inner zip it contains, walk cves/YYYY/Nxxx/*.json, then
    delete the temp file no matter what."""
    import requests
    written = 0
    tmp = tempfile.NamedTemporaryFile(prefix="mynes_cvelist_", suffix=".zip", delete=False)
    tmp_path = tmp.name
    try:
        with requests.get(url, timeout=600, headers={"User-Agent": _UA}, stream=True) as resp:
            resp.raise_for_status()
            for chunk in resp.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    tmp.write(chunk)
        tmp.close()
        with zipfile.ZipFile(tmp_path) as outer:
            # The outer zip contains a single inner .zip with all the records.
            inner_names = [n for n in outer.namelist() if n.endswith(".zip")]
            if inner_names:
                for inner_name in inner_names:
                    with outer.open(inner_name) as inner_fh:
                        with zipfile.ZipFile(io.BytesIO(inner_fh.read())) as inner:
                            written += upsert_records(
                                _iter_cve_jsons_from_zip(inner), source="cvelistV5-full")
            else:
                # Not actually nested - treat the outer zip as the record zip.
                written += upsert_records(
                    _iter_cve_jsons_from_zip(outer), source="cvelistV5-full")
    finally:
        try:
            tmp.close()
        except Exception:  # noqa: BLE001
            pass
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
    return written


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------

def demo():
    """Hermetic self-check: upsert two fabricated CVE-5.x records into a throw-
    away DB, then get_record / search / stats. Never touches the real DB."""
    # Patch THIS module's own globals (works whether run as __main__ or
    # imported), so the throwaway DB is used by every function below.
    import sys
    store = sys.modules[__name__]

    tmpdir = tempfile.mkdtemp(prefix="mynes_cvestore_demo_")
    orig = store._db_path
    store._db_path = lambda: os.path.join(tmpdir, "cve_records.db")
    try:
        # -- network-relevance filter (pure, no DB) ----------------------
        # A local-only overflow (AV:L) is dropped; a networked one (AV:N or a
        # network keyword) is kept.
        local_only = {"cveMetadata": {"cveId": "CVE-2099-8000"}, "containers": {"cna": {
            "title": "local integer overflow", "descriptions": [{"lang": "en", "value": "overflow via a local file"}],
            "metrics": [{"cvssV3_1": {"vectorString": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"}}]}}}
        assert is_network_relevant(local_only) is False
        assert _record_row(local_only, "x") is None
        by_keyword = {"cveMetadata": {"cveId": "CVE-2099-8001"}, "containers": {"cna": {
            "title": "router web RCE", "descriptions": [{"lang": "en", "value": "unauthenticated remote code on a router"}]}}}
        assert is_network_relevant(by_keyword) is True

        rec_a = {
            "cveMetadata": {"cveId": "CVE-2099-0001",
                            "datePublished": "2099-01-01T00:00:00Z",
                            "dateUpdated": "2099-02-01T00:00:00Z"},
            "containers": {"cna": {
                "title": "Fabricated flaw A",
                "descriptions": [{"lang": "en", "value": "A test description alpha."}],
                "references": [{"url": "https://www.cve.org/CVERecord?id=CVE-2099-0001"}],
                "metrics": [{"cvssV3_1": {"baseScore": 9.1, "baseSeverity": "CRITICAL",
                                          "attackVector": "NETWORK"}}],
            }},
        }
        rec_b = {
            "cveMetadata": {"cveId": "CVE-2099-0002",
                            "datePublished": "2099-03-01T00:00:00Z"},
            "containers": {"cna": {
                "title": "Fabricated flaw B",
                "descriptions": [{"lang": "en", "value": "A test description beta."}],
                "references": [{"url": "https://example.com/b"}],
                "metrics": [{"cvssV3_1": {"baseScore": 5.0, "baseSeverity": "MEDIUM",
                                          "attackVector": "ADJACENT_NETWORK"}}],
            }},
        }
        # A junk record must be skipped, not counted, not raise.
        junk = {"no": "cveMetadata"}

        written = upsert_records([rec_a, rec_b, junk])
        assert written == 2, written

        st = stats()
        assert st["count"] == 2, st
        assert st["last_updated"], st

        got = get_record("CVE-2099-0001")
        assert got and got["title"] == "Fabricated flaw A"
        assert got["severity"] == "critical" and got["cvss"] == 9.1
        assert got["refs"].endswith("CVE-2099-0001")
        # Case-insensitive id lookup.
        assert get_record("cve-2099-0001")["cve_id"] == "CVE-2099-0001"
        assert get_record("CVE-0000-0000") is None

        # Search matches id and free text, newest (by published) first.
        by_id = search("CVE-2099-0002")
        assert len(by_id) == 1 and by_id[0]["cve_id"] == "CVE-2099-0002"
        by_text = search("test description")
        assert len(by_text) == 2
        assert by_text[0]["cve_id"] == "CVE-2099-0002"   # published 2099-03 first
        assert search("nothing-matches-this") == []

        # An upsert of an existing id replaces, not duplicates.
        rec_a2 = dict(rec_a)
        rec_a2["containers"] = {"cna": {"title": "Fabricated flaw A v2",
                                        "descriptions": [{"lang": "en", "value": "updated"}],
                                        "metrics": [{"cvssV3_1": {"attackVector": "NETWORK"}}]}}
        upsert_records([rec_a2])
        assert stats()["count"] == 2
        assert get_record("CVE-2099-0001")["title"] == "Fabricated flaw A v2"

        print("cve_store: OK")
        return True
    finally:
        store._db_path = orig
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    demo()
