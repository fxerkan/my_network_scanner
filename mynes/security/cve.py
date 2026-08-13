"""Attack-surface and vulnerability risk assessment for one device.

L0p4Map's CVE feature calls out to ``nmap --script vulners,vuln`` against a
live vulners.com feed - a realtime service the user explicitly asked to
leave out. This is the offline equivalent: a curated, versioned table of
well-documented CVEs matched against the banners/services
``analysis/fingerprint.py`` already collected (no extra probing, no network
calls beyond what a normal scan already did), plus a handful of
port-based "attack surface" exposures that are not tied to one CVE at all
(Telnet enabled, VNC reachable, SMB/NetBIOS reachable).

This is explicitly *not* a vulnerability scanner and must never be
presented as one: it is a small, hand-curated pattern table (see
``CVE_PATTERNS`` below), the same shape as ``fingerprint.py``'s vendor/
hint tuples, and it only fires on evidence specific enough to name a real
CVE. Where the evidence proves a *service* but not the exact patched/
unpatched version (SMB without a version, RDP without a build number), the
finding is worded as "verify" rather than "vulnerable" - the whole point of
a curated table over a live feed is that it can afford to be honest about
what it does not know.

    python -m mynes.security.cve      # self-check
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone

from mynes.paths import config_file

# ---------------------------------------------------------------------------
# Curated CVE patterns. Each: id, title, severity, a `match` dict of
# {signal: regex} (ALL must match - most entries use exactly one), an
# optional `ports` set (open port intersection required too), description,
# reference. Extend this list the same way fingerprint.py's hint tuples are
# extended: one well-documented entry at a time, real CVE ID, real regex.
# ---------------------------------------------------------------------------

CVE_PATTERNS = [
    {
        'id': 'CVE-2011-2523', 'title': 'vsftpd 2.3.4 backdoor', 'severity': 'critical',
        'match': {'ftp': r'vsftpd\s*2\.3\.4'},
        'description': 'This exact vsftpd build shipped with a backdoor for several days in '
                       '2011: a username ending in ":)" opens a shell on port 6200. Any install '
                       'still running 2.3.4 should be upgraded immediately.',
        'reference': 'https://www.cve.org/CVERecord?id=CVE-2011-2523',
    },
    {
        'id': 'CVE-2015-3306', 'title': 'ProFTPD mod_copy unauthenticated file copy', 'severity': 'high',
        'match': {'ftp': r'proftpd\s*1\.3\.5'},
        'description': 'ProFTPD 1.3.5 with mod_copy enabled lets an unauthenticated client copy '
                       'files anywhere the FTP process can write, which is a path to remote code '
                       'execution. Verify mod_copy is disabled or the server is patched.',
        'reference': 'https://www.cve.org/CVERecord?id=CVE-2015-3306',
    },
    {
        'id': 'CVE-2021-41773', 'title': 'Apache HTTP Server 2.4.49 path traversal', 'severity': 'critical',
        'match': {'http': r'apache/2\.4\.49\b'},
        'description': 'Apache 2.4.49 allows path traversal to read files outside the document '
                       'root, and to RCE when CGI/mod_cgi is enabled (CVE-2021-42013 patched the '
                       'same class again in 2.4.50). Upgrade to 2.4.51 or later.',
        'reference': 'https://www.cve.org/CVERecord?id=CVE-2021-41773',
    },
    {
        'id': 'CVE-2021-42013', 'title': 'Apache HTTP Server 2.4.50 path traversal/RCE', 'severity': 'critical',
        'match': {'http': r'apache/2\.4\.50\b'},
        'description': "The fix for CVE-2021-41773 in 2.4.50 was incomplete - this build is "
                       "still exploitable the same way. Upgrade to 2.4.51 or later.",
        'reference': 'https://www.cve.org/CVERecord?id=CVE-2021-42013',
    },
    {
        'id': 'CVE-2017-7921', 'title': 'Hikvision camera authentication bypass', 'severity': 'high',
        'match': {'http': r'hikvision', 'rtsp': r'hikvision'},
        'match_any': True,
        'description': 'Older Hikvision camera/NVR firmware has had multiple authentication-'
                       'bypass and credential-disclosure vulnerabilities (CVE-2017-7921 and '
                       'related). This only proves the device *is* Hikvision gear, not its '
                       'firmware version - check for a firmware update from Hikvision.',
        'reference': 'https://www.cve.org/CVERecord?id=CVE-2017-7921',
    },
    {
        'id': 'CVE-2021-33044', 'title': 'Dahua camera authentication bypass', 'severity': 'high',
        'match': {'http': r'dahua', 'rtsp': r'dahua'}, 'match_any': True,
        'description': 'Dahua and Dahua-derived (OEM) camera/NVR firmware has had authentication-'
                       'bypass vulnerabilities (CVE-2021-33044/33045). This only proves the '
                       'device is Dahua-family gear, not its firmware version - check for an '
                       'update.',
        'reference': 'https://www.cve.org/CVERecord?id=CVE-2021-33044',
    },
    {
        'id': 'CVE-2018-9995', 'title': 'Generic TBK-derived DVR/NVR credential disclosure', 'severity': 'high',
        'match': {}, 'ports': {34567, 37777},
        'description': 'Ports 34567/37777 are the proprietary control ports used by TBK-derived '
                       'DVR/NVR firmware (sold under many brand names). This firmware family has '
                       'had credential-disclosure and unauthenticated-RCE vulnerabilities '
                       '(CVE-2018-9995 and others). Verify the firmware is current and the port '
                       'is not reachable from outside the LAN.',
        'reference': 'https://www.cve.org/CVERecord?id=CVE-2018-9995',
    },
]

# ---------------------------------------------------------------------------
# Attack-surface exposures. Not a specific CVE - a service that is a common
# attack target by nature, worded as "verify"/"check", never "vulnerable".
# ---------------------------------------------------------------------------

EXPOSURE_RULES = [
    {'ports': {23}, 'severity': 'high', 'title': 'Telnet is open',
     'description': 'Telnet sends credentials in cleartext and has no modern security model. '
                    'If this is a device admin console, replace it with SSH or the vendor app '
                    'wherever the firmware allows disabling Telnet.'},
    {'ports': {21}, 'severity': 'medium', 'title': 'FTP is open',
     'description': 'FTP sends credentials in cleartext. Check whether anonymous login is '
                    'possible, and prefer SFTP/FTPS if the device supports it.'},
    {'ports': {445, 139}, 'severity': 'medium', 'title': 'SMB/NetBIOS is open',
     'description': 'If this host still has SMBv1 enabled, it is vulnerable to EternalBlue '
                    '(CVE-2017-0144, the WannaCry/NotPetya vector). Confirm SMBv1 is disabled '
                    'and only SMBv2/3 is offered.'},
    {'ports': {3389}, 'severity': 'medium', 'title': 'RDP is open',
     'description': 'RDP is a high-value target for credential stuffing and, on unpatched '
                    'Windows builds, BlueKeep (CVE-2019-0708). Confirm the OS is patched and '
                    'RDP is not reachable from outside the LAN.'},
    {'ports': {5900}, 'severity': 'medium', 'title': 'VNC is open',
     'description': 'Many VNC servers ship with a weak or no password by default. Confirm a '
                    'strong password is set and VNC is not reachable from outside the LAN.'},
    {'ports': {161}, 'severity': 'low', 'title': 'SNMP is open',
     'description': 'Confirm the SNMP community string is not left at the "public"/"private" '
                    'defaults - a common way to read (or on some devices, write) configuration.'},
    {'ports': {9100}, 'severity': 'low', 'title': 'Raw printer port (JetDirect) is open',
     'description': 'Port 9100 accepts raw print jobs with no authentication on most printers - '
                    'expected for a printer, but confirm this is one before treating it as normal.'},
    {'ports': {1900}, 'severity': 'low', 'title': 'UPnP/SSDP is open',
     'description': 'UPnP lets any device on the LAN ask this one to open ports on the router. '
                    'Informational on a trusted LAN; worth disabling on anything internet-facing.'},
]

_SEVERITY_WEIGHT = {'critical': 40, 'high': 25, 'medium': 12, 'low': 5}
_SEVERITY_ORDER = ['critical', 'high', 'medium', 'low']
_VALID_SEVERITIES = set(_SEVERITY_ORDER)

# The offline overlay: a downloadable JSON file that AUGMENTS the built-in
# CVE_PATTERNS above. This is deliberately still not a live NVD/vulners feed -
# it is the same hand-curated shape, just refreshable without a code release.
# The built-in list is always the seed/fallback; a downloaded entry with the
# same `id` overrides its built-in twin, everything else is merged in.
CVE_PATTERNS_FILE = 'cve_patterns.json'

# Public, always-current CVE metadata sources - free, no API key. We do NOT
# download the whole CVE corpus (that would make this a live scanner, which the
# module docstring refuses): matching stays curated. What "sync" does is refresh
# the *metadata* (title, description, references, CVSS severity) of the CVE ids
# we already know from these authoritative feeds, so the Security page always
# shows current, sourced detail. The banner-match regexes are preserved.
#   cveorg  - the official CVE.org record API (MITRE CVE Services)
#   circl   - CIRCL's aggregator, same CVE-5.x JSON shape, handy as a fallback
CVE_PROVIDERS = {
    'cveorg': 'https://cveawg.mitre.org/api/cve/{id}',
    'circl': 'https://cve.circl.lu/api/cve/{id}',
}
DEFAULT_CVE_SOURCE = 'cveorg'
_ENRICH_CAP = 100            # never fan out to more than this many ids per sync


# ---------------------------------------------------------------------------
# Overlay loading, validation, sync and status. Everything here degrades to
# the built-in list: a missing, corrupt or hostile feed must never break an
# assessment (that is the whole reason the offline table exists).
# ---------------------------------------------------------------------------

def _valid_pattern(entry: dict) -> bool:
    """A downloaded entry is only kept if every field is well-formed AND every
    regex in `match` compiles. One bad entry is dropped, never the whole feed."""
    if not isinstance(entry, dict):
        return False
    if not isinstance(entry.get('id'), str) or not entry['id'].strip():
        return False
    if not isinstance(entry.get('title'), str) or not entry['title'].strip():
        return False
    if entry.get('severity') not in _VALID_SEVERITIES:
        return False
    match = entry.get('match')
    if not isinstance(match, dict):
        return False
    for signal, rx in match.items():
        if not isinstance(signal, str) or not isinstance(rx, str):
            return False
        try:
            re.compile(rx)
        except re.error:
            return False
    if not isinstance(entry.get('description'), str) or not entry['description'].strip():
        return False
    if not isinstance(entry.get('reference'), str) or not entry['reference'].strip():
        return False
    return True


def _read_overlay() -> dict:
    """The raw overlay envelope from disk, or {} when absent/corrupt."""
    path = config_file(CVE_PATTERNS_FILE)
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding='utf-8') as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _custom_patterns() -> list:
    """Validated overlay patterns only (built-ins excluded). Invalid dropped.
    `ports` round-trips through JSON as a list; matching needs a set."""
    overlay = _read_overlay()
    raw = overlay.get('patterns') if isinstance(overlay.get('patterns'), list) else []
    out = []
    for p in raw:
        if not _valid_pattern(p):
            continue
        p = dict(p)
        if isinstance(p.get('ports'), (list, set)):
            p['ports'] = set(p['ports'])
        out.append(p)
    return out


def load_patterns() -> list:
    """Built-in CVE_PATTERNS merged with the validated overlay, de-duped by
    `id`. A downloaded entry with the same id overrides the built-in one; the
    built-in list stands alone when no overlay file exists."""
    merged = {p['id']: p for p in CVE_PATTERNS}
    for p in _custom_patterns():
        merged[p['id']] = p        # downloaded wins on id collision
    # Keep built-in ordering first, then any genuinely new downloaded ids.
    builtin_ids = [p['id'] for p in CVE_PATTERNS]
    extra_ids = [pid for pid in merged if pid not in set(builtin_ids)]
    return [merged[pid] for pid in builtin_ids + extra_ids]


def cve_db_status() -> dict:
    """Counts + provenance for the Settings card - mirrors OUI's get_stats().

    Also reports the official CVE List V5 reference store (records_count /
    records_last_updated) so the card can show the "update like OUI" corpus
    alongside the curated pattern counts. The store is fully optional."""
    overlay = _read_overlay()
    custom = _custom_patterns()
    try:
        from mynes.security.cve_store import stats as _record_stats
        rs = _record_stats()
    except Exception:  # noqa: BLE001 - the store is optional; never break status
        rs = {'count': 0, 'last_updated': None}
    return {
        'builtin_count': len(CVE_PATTERNS),
        'custom_count': len(custom),
        'total': len(load_patterns()),
        'last_updated': overlay.get('fetched_at'),
        'source': overlay.get('source'),
        'records_count': rs.get('count', 0),
        'records_last_updated': rs.get('last_updated'),
    }


def sync_cve_list_v5(mode: str = 'delta') -> dict:
    """Adopt the official CVE Project corpus (CVE List V5) into the reference
    store - the "update like OUI" path. Thin passthrough to
    ``cve_store.sync_cve_list_v5`` so the Settings sync flow has one entry point
    here. Offline-safe: never raises."""
    try:
        from mynes.security.cve_store import sync_cve_list_v5 as _sync
    except Exception as e:  # noqa: BLE001
        return {'ok': False, 'error': str(e)}
    return _sync(mode)


def _save_overlay(patterns: list, source: str) -> dict:
    """Write the validated overlay envelope. Owner-readable data, not secret,
    but kept in the config dir alongside the OUI/device-type overlays."""
    valid = []
    for p in patterns:
        if not _valid_pattern(p):
            continue
        p = dict(p)
        if isinstance(p.get('ports'), set):      # sets aren't JSON-serialisable
            p['ports'] = sorted(p['ports'])
        valid.append(p)
    envelope = {
        'source': source,
        'fetched_at': datetime.now(timezone.utc).isoformat(),
        'count': len(valid),
        'patterns': valid,
    }
    path = config_file(CVE_PATTERNS_FILE)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as fh:
        json.dump(envelope, fh, ensure_ascii=False, indent=2)
    return envelope


def import_patterns(patterns) -> dict:
    """Save a user-supplied patterns list (upload/paste). Validates, drops the
    invalid, never raises -> {ok, ...status}. Mirrors the OUI import path."""
    try:
        if isinstance(patterns, dict) and isinstance(patterns.get('patterns'), list):
            patterns = patterns['patterns']
        if not isinstance(patterns, list):
            return {'ok': False, 'error': 'expected a JSON array of patterns'}
        valid = [p for p in patterns if _valid_pattern(p)]
        if not valid:
            return {'ok': False, 'error': 'no valid CVE patterns in payload'}
        _save_overlay(valid, source='import')
        return {'ok': True, 'imported': len(valid),
                'dropped': len(patterns) - len(valid), **cve_db_status()}
    except Exception as e:  # noqa: BLE001 - an import must never crash the page
        return {'ok': False, 'error': str(e)}


_CVSS_TO_SEVERITY = {'CRITICAL': 'critical', 'HIGH': 'high', 'MEDIUM': 'medium', 'LOW': 'low'}


def _extract_meta(record: dict) -> dict:
    """Pull the fields we care about out of a CVE-5.x record (same shape from
    cve.org and CIRCL). Returns only the keys it could find; the caller layers
    these over the curated pattern so a missing field just keeps the built-in
    value. Pure - unit-tested in demo() without any network."""
    cna = (record.get('containers') or {}).get('cna') or {}
    meta: dict = {}

    title = cna.get('title')
    if isinstance(title, str) and title.strip():
        meta['title'] = title.strip()

    for d in cna.get('descriptions') or []:
        if (d.get('lang') or '').lower().startswith('en') and d.get('value'):
            meta['description'] = d['value'].strip()
            break

    for ref in cna.get('references') or []:
        if ref.get('url'):
            meta['reference'] = ref['url']
            break

    # CVSS can live under the CNA metrics or an ADP container; take the first
    # baseSeverity we find and map it onto our four-bucket scale.
    metric_blocks = list(cna.get('metrics') or [])
    for adp in record.get('containers', {}).get('adp') or []:
        metric_blocks += adp.get('metrics') or []
    for m in metric_blocks:
        for key, val in m.items():
            if key.lower().startswith('cvss') and isinstance(val, dict):
                sev = _CVSS_TO_SEVERITY.get(str(val.get('baseSeverity', '')).upper())
                if val.get('baseScore') is not None:
                    meta['cvss'] = val['baseScore']
                if sev:
                    meta['severity'] = sev
                break
        if 'cvss' in meta or 'severity' in meta:
            break
    return meta


def _fetch_cve_record(cve_id: str, provider: str):
    """One CVE record from a provider, or None on any failure. Never raises."""
    import requests
    tmpl = CVE_PROVIDERS[provider]
    resp = requests.get(tmpl.format(id=cve_id), timeout=12,
                        headers={'User-Agent': 'MyNeS/CVE-sync'})
    resp.raise_for_status()
    return resp.json()


def sync_cve_data(source: str | None = None) -> dict:
    """Refresh CVE metadata from a public, always-current source.

    `source` is a provider key ('cveorg'/'circl') - the normal case - OR a raw
    URL to a MyNeS-native patterns overlay (advanced/offline mirror). Provider
    sync enriches the metadata of every CVE id we already know while KEEPING the
    curated banner-match regexes, so it can never invent a false finding.

    Offline-safe: never raises; a failed feed leaves the built-in table intact.
    """
    source = source or DEFAULT_CVE_SOURCE
    try:
        import requests  # noqa: F401 - presence check; used in helpers
    except ImportError:
        return {'ok': False, 'error': 'requests not installed'}

    # Advanced path: a raw URL to a native overlay (list/{patterns:[...]}).
    if source not in CVE_PROVIDERS:
        try:
            import requests
            resp = requests.get(source, timeout=15, headers={'User-Agent': 'MyNeS/CVE-sync'})
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:  # noqa: BLE001 - network/parse failures expected
            return {'ok': False, 'error': str(e)}
        patterns = data.get('patterns') if isinstance(data, dict) else data
        if not isinstance(patterns, list):
            return {'ok': False, 'error': 'feed did not contain a patterns array'}
        valid = [p for p in patterns if _valid_pattern(p)]
        if not valid:
            return {'ok': False, 'error': 'feed contained no valid CVE patterns'}
        _save_overlay(valid, source=source)
        return {'ok': True, 'fetched': len(patterns), 'kept': len(valid),
                'dropped': len(patterns) - len(valid), **cve_db_status()}

    # Provider path: enrich the ids we already track (built-in + overlay).
    base = {p['id']: dict(p) for p in load_patterns()}
    ids = [pid for pid in base if re.match(r'^CVE-\d{4}-\d+$', pid, re.I)][:_ENRICH_CAP]
    enriched, failed = [], 0
    for cve_id in ids:
        try:
            record = _fetch_cve_record(cve_id, source)
            meta = _extract_meta(record)
        except Exception:  # noqa: BLE001 - one dead id must not kill the sync
            failed += 1
            continue
        merged = {**base[cve_id], **meta}   # curated match/ports preserved
        if _valid_pattern(merged):
            enriched.append(merged)
        else:
            failed += 1

    if not enriched:
        return {'ok': False, 'error': f'no CVEs could be refreshed from {source} '
                                      f'({failed} failed) - check connectivity'}
    _save_overlay(enriched, source=source)
    return {'ok': True, 'enriched': len(enriched), 'failed': failed, **cve_db_status()}


def _signal_text(signals: dict, key: str) -> str:
    """One signal, flattened to searchable text. Mirrors fingerprint._corpus,
    kept separate because a CVE match needs to know *which* signal matched,
    not just whether something in the whole corpus did."""
    if key in ('ssh', 'ftp', 'vendor', 'hostname'):
        return (signals.get(key) or '').lower()
    if key == 'http':
        parts = []
        for banner in signals.get('http') or []:
            parts += [banner.get('server', ''), banner.get('powered_by', ''), banner.get('title', '')]
        return ' '.join(p for p in parts if p).lower()
    if key == 'rtsp':
        rtsp = signals.get('rtsp') or {}
        return ' '.join([rtsp.get('server', ''), rtsp.get('realm', '')]).lower()
    if key == 'smb':
        smb = signals.get('smb') or {}
        return ' '.join([smb.get('netbios_name', ''), smb.get('workgroup', '')]).lower()
    return ''


def _enrich_from_official_db(finding: dict) -> dict:
    """Overlay the authoritative title/description/reference/cvss/severity from
    the official CVE List V5 SQLite store onto a finding, keyed by cve_id.

    Order of precedence: official DB record > JSON overlay/built-in (already in
    the finding). Fully guarded - a missing/locked DB just leaves the curated
    values in place. The banner-match evidence is never touched here."""
    cid = finding.get('cve_id')
    if not cid or not re.match(r'^CVE-\d{4}-\d+$', cid, re.I):
        return finding
    try:
        from mynes.security.cve_store import get_record
        rec = get_record(cid)
    except Exception:  # noqa: BLE001 - enrichment is best-effort, never fatal
        return finding
    if not rec:
        return finding
    if rec.get('title'):
        finding['title'] = rec['title']
    if rec.get('description'):
        finding['description'] = rec['description']
    if rec.get('refs'):
        finding['reference'] = rec['refs']
    if rec.get('severity') in _VALID_SEVERITIES:
        finding['severity'] = rec['severity']
    if rec.get('cvss') is not None:
        finding['cvss'] = rec['cvss']
    finding['source'] = 'cvelistV5'
    return finding


def match_cves(signals: dict, open_ports: set) -> list:
    """-> every ``CVE_PATTERNS`` entry whose conditions are all satisfied,
    enriched from the official CVE List V5 store when the id is present."""
    findings = []
    for pattern in load_patterns():
        conditions = pattern.get('match') or {}
        checks = [bool(re.search(rx, _signal_text(signals, key))) for key, rx in conditions.items()]
        if conditions:
            ok = any(checks) if pattern.get('match_any') else all(checks)
        else:
            ok = True   # a port-only pattern (no banner condition at all)
        if not ok:
            continue
        required_ports = pattern.get('ports')
        if required_ports and not (required_ports & open_ports):
            continue
        finding = {
            'cve_id': pattern['id'], 'title': pattern['title'], 'severity': pattern['severity'],
            'description': pattern['description'], 'reference': pattern['reference'],
        }
        if pattern.get('cvss') is not None:      # present only after enrichment
            finding['cvss'] = pattern['cvss']
        finding = _enrich_from_official_db(finding)
        findings.append(finding)
    return findings


def surface_exposures(open_ports: set) -> list:
    """-> every ``EXPOSURE_RULES`` entry whose port is actually open here."""
    return [
        {'title': rule['title'], 'severity': rule['severity'], 'description': rule['description']}
        for rule in EXPOSURE_RULES if rule['ports'] & open_ports
    ]


def risk_score(findings: list, exposures: list) -> int:
    """0-100. Findings count for more than exposures - a named CVE is
    stronger evidence than "this port is generally worth locking down"."""
    score = sum(_SEVERITY_WEIGHT.get(f['severity'], 0) for f in findings)
    score += sum(_SEVERITY_WEIGHT.get(e['severity'], 0) // 2 for e in exposures)
    return min(100, score)


def risk_level(score: int, findings: list | None = None, exposures: list | None = None) -> str:
    """The level tracks the WORST single item on the device, not just the
    numeric score - a high-severity item (a critical CVE match, or a
    high exposure like open Telnet) means the device *is* that severity, even
    if the score alone wouldn't reach the band. Otherwise a device whose only
    problem is cleartext Telnet (a genuinely high exposure) reads "low", which
    is misleading. Exposures count here the same as findings; the finding-vs-
    exposure weighting lives in risk_score(), not in the badge."""
    severities = {f['severity'] for f in (findings or [])} | {e['severity'] for e in (exposures or [])}
    if 'critical' in severities or score >= 70:
        return 'critical'
    if 'high' in severities or score >= 40:
        return 'high'
    if 'medium' in severities or score >= 15:
        return 'medium'
    if score > 0 or severities:
        return 'low'
    return 'none'


def _is_docker_internal(device: dict) -> bool:
    """Docker bridge gateways and containers are internal to the host, not LAN
    attack surface. Every br-* gateway is just the host under another IP, so
    scanning them flagged the host's SMB/VNC once per bridge - a dozen identical
    'VNC is open' rows on addresses nothing on the LAN can even reach. Their MAC
    always sits in Docker's 02:42:xx range; the type carries 'docker' too."""
    mac = (device.get('mac') or '').lower().replace('-', ':')
    if mac.startswith('02:42:'):
        return True
    return 'docker' in (device.get('device_type') or '').lower()


def assess_device(device: dict) -> dict:
    """Everything the Security tab needs for one device, built entirely
    from data a normal scan already collected - no new network I/O."""
    if _is_docker_internal(device):
        return {'ip': device.get('ip'), 'risk_score': 0, 'risk_level': 'none',
                'findings': [], 'exposures': [], 'docker_internal': True}
    fp = device.get('fingerprint') or {}
    signals = {
        'ssh': fp.get('ssh'), 'ftp': fp.get('ftp'), 'http': fp.get('http') or [],
        'rtsp': fp.get('rtsp'), 'smb': fp.get('smb'),
        'vendor': device.get('vendor'), 'hostname': device.get('hostname'),
    }
    open_ports = {
        p['port'] if isinstance(p, dict) else p
        for p in (device.get('open_ports') or []) if p
    }

    findings = match_cves(signals, open_ports)
    exposures = surface_exposures(open_ports)
    score = risk_score(findings, exposures)

    findings.sort(key=lambda f: _SEVERITY_ORDER.index(f['severity']))
    exposures.sort(key=lambda e: _SEVERITY_ORDER.index(e['severity']))

    return {
        'ip': device.get('ip'), 'risk_score': score, 'risk_level': risk_level(score, findings, exposures),
        'findings': findings, 'exposures': exposures,
    }


def fleet_summary(devices: list) -> dict:
    """Attack-surface overview across every device - the highest-risk hosts
    first, for a "what should I fix first" view rather than clicking
    through every device one at a time."""
    assessed = [assess_device(d) for d in devices if d.get('ip')]
    assessed.sort(key=lambda a: a['risk_score'], reverse=True)
    return {
        'devices': assessed,
        'total_findings': sum(len(a['findings']) for a in assessed),
        'total_exposures': sum(len(a['exposures']) for a in assessed),
        'at_risk_count': sum(1 for a in assessed if a['risk_score'] > 0),
    }


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------

def demo():
    """Hermetic self-check: a real synced overlay on disk must neither change
    the result nor be clobbered by the run, so back it up, test on a clean
    slate, and restore it no matter what."""
    path = config_file(CVE_PATTERNS_FILE)
    backup = None
    if os.path.exists(path):
        with open(path, encoding='utf-8') as fh:
            backup = fh.read()
        os.remove(path)
    try:
        return _demo_body()
    finally:
        if backup is not None:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'w', encoding='utf-8') as fh:
                fh.write(backup)
        elif os.path.exists(path):
            os.remove(path)


def _demo_body():
    # The textbook case this module exists for: an exact, unambiguous match.
    backdoored_ftp = {'ip': '192.168.1.50', 'fingerprint': {'ftp': '220 (vsFTPd 2.3.4)'},
                      'open_ports': [{'port': 21}]}
    result = assess_device(backdoored_ftp)
    assert result['risk_level'] == 'critical', result
    assert any(f['cve_id'] == 'CVE-2011-2523' for f in result['findings'])

    # A patched vsftpd on the same port must not match - the regex is exact.
    patched_ftp = {'ip': '192.168.1.51', 'fingerprint': {'ftp': '220 (vsFTPd 3.0.3)'},
                   'open_ports': [{'port': 21}]}
    result = assess_device(patched_ftp)
    assert not any(f['cve_id'] == 'CVE-2011-2523' for f in result['findings'])
    # It still gets the generic "FTP is open" exposure - that is not version-specific.
    assert any(e['title'] == 'FTP is open' for e in result['exposures'])

    # A clean device: no findings, no exposures, risk 0/"none".
    clean = {'ip': '192.168.1.52', 'fingerprint': {}, 'open_ports': [{'port': 443}]}
    result = assess_device(clean)
    assert result['risk_score'] == 0 and result['risk_level'] == 'none'
    assert result['findings'] == [] and result['exposures'] == []

    # A device answering nothing but "this is a TBK-derived DVR" still gets
    # flagged from the port pair alone - no banner text needed.
    dvr = {'ip': '192.168.1.53', 'fingerprint': {}, 'open_ports': [{'port': 34567}, {'port': 80}]}
    result = assess_device(dvr)
    assert any(f['cve_id'] == 'CVE-2018-9995' for f in result['findings'])

    # Hikvision named in either the HTTP banner or the RTSP realm is enough -
    # match_any means the two conditions are OR'd, not AND'd.
    cam = {'ip': '192.168.1.54', 'open_ports': [{'port': 554}],
          'fingerprint': {'rtsp': {'server': '', 'realm': 'Hikvision Q3'}, 'http': []}}
    result = assess_device(cam)
    assert any(f['cve_id'] == 'CVE-2017-7921' for f in result['findings'])

    # Telnet open is a "high" exposure with no CVE attached - and a device
    # whose only problem is a high exposure must NOT read "low" (the whole
    # point of this fix): the badge tracks the worst item.
    telnet_host = {'ip': '192.168.1.55', 'fingerprint': {}, 'open_ports': [{'port': 23}]}
    result = assess_device(telnet_host)
    assert result['exposures'][0]['title'] == 'Telnet is open'
    assert result['exposures'][0]['severity'] == 'high'
    assert result['risk_level'] == 'high', result   # not 'low' despite score 12

    # risk_level thresholds are monotonic and match the documented buckets.
    assert risk_level(0) == 'none'
    assert risk_level(10) == 'low'
    assert risk_level(20) == 'medium'
    assert risk_level(45) == 'high'
    assert risk_level(80) == 'critical'
    # ...and a single critical finding forces "critical" even at a low score.
    assert risk_level(5, [{'severity': 'critical'}]) == 'critical'
    # A high exposure alone floors the level to "high"; a medium one to "medium".
    assert risk_level(12, [], [{'severity': 'high'}]) == 'high'
    assert risk_level(6, [], [{'severity': 'medium'}]) == 'medium'

    # A fleet summary sorts the worst device first.
    summary = fleet_summary([clean, backdoored_ftp, telnet_host])
    assert summary['devices'][0]['ip'] == '192.168.1.50'
    assert summary['at_risk_count'] == 2

    # -- overlay: loader, validation, status ------------------------------
    # A bare built-in load has no custom entries and the counts add up.
    status = cve_db_status()
    assert status['builtin_count'] == len(CVE_PATTERNS)
    assert status['total'] == status['builtin_count'] + status['custom_count']

    # _valid_pattern is the gate the feed must pass. A good entry passes;
    # a bad-regex entry, a bad severity, and a missing field all fail.
    good = {'id': 'CVE-9999-0001', 'title': 'x', 'severity': 'high',
            'match': {'http': r'foo\d+'}, 'description': 'd', 'reference': 'r'}
    assert _valid_pattern(good)
    assert not _valid_pattern({**good, 'match': {'http': r'(unclosed'}})   # bad regex
    assert not _valid_pattern({**good, 'severity': 'urgent'})             # bad severity
    assert not _valid_pattern({k: v for k, v in good.items() if k != 'reference'})

    # import_patterns writes an overlay; a bad-regex entry is dropped, a good
    # one with a NEW id augments the built-ins, and an override by id wins.
    override = {'id': 'CVE-2011-2523', 'title': 'overridden', 'severity': 'low',
                'match': {'ftp': r'vsftpd'}, 'description': 'd', 'reference': 'r'}
    bad = {'id': 'CVE-9999-9999', 'title': 'x', 'severity': 'high',
           'match': {'http': r'(nope'}, 'description': 'd', 'reference': 'r'}
    result = import_patterns([good, override, bad])
    try:
        assert result['ok'] and result['imported'] == 2 and result['dropped'] == 1
        merged = {p['id']: p for p in load_patterns()}
        assert merged['CVE-2011-2523']['title'] == 'overridden'   # id override wins
        assert 'CVE-9999-0001' in merged                          # new id augments
        st2 = cve_db_status()
        assert st2['custom_count'] == 2
        # One custom entry overrides a built-in id (no net new row), the other
        # is a genuinely new id (one net new row) -> total = builtin + 1.
        assert st2['total'] == st2['builtin_count'] + 1
    finally:
        # Clean up the overlay so the self-check leaves no artefact behind.
        _p = config_file(CVE_PATTERNS_FILE)
        if os.path.exists(_p):
            os.remove(_p)
    assert cve_db_status()['custom_count'] == 0

    # sync with a plainly unreachable URL degrades, never raises.
    bad_sync = sync_cve_data('http://127.0.0.1:0/nope.json')
    assert bad_sync['ok'] is False and 'error' in bad_sync

    # _extract_meta pulls title/description/reference/severity out of a CVE-5.x
    # record (the shape cve.org and CIRCL both return) - pure, no network.
    record = {'containers': {'cna': {
        'title': 'Example flaw',
        'descriptions': [{'lang': 'en', 'value': 'A serious bug.'}],
        'references': [{'url': 'https://www.cve.org/CVERecord?id=CVE-2011-2523'}],
        'metrics': [{'cvssV3_1': {'baseScore': 9.8, 'baseSeverity': 'CRITICAL'}}],
    }}}
    meta = _extract_meta(record)
    assert meta['title'] == 'Example flaw' and meta['description'] == 'A serious bug.'
    assert meta['reference'].endswith('CVE-2011-2523')
    assert meta['severity'] == 'critical' and meta['cvss'] == 9.8
    # An empty record yields an empty overlay - the curated pattern is kept as-is.
    assert _extract_meta({}) == {}
    assert set(CVE_PROVIDERS) == {'cveorg', 'circl'}

    # cve_db_status now reports the official CVE List V5 store counts too - the
    # keys always exist even when the store is empty/absent.
    st = cve_db_status()
    assert 'records_count' in st and 'records_last_updated' in st

    # Enrichment overlays an official DB record onto a finding by id, and is a
    # no-op when the store has no such record. Point the store at a throwaway
    # DB so the real one is untouched.
    import mynes.security.cve_store as _store
    import tempfile as _tf, os as _os2, shutil as _sh
    _tmpdir = _tf.mkdtemp(prefix='mynes_cve_enrich_')
    _orig = _store._db_path
    _store._db_path = lambda: _os2.path.join(_tmpdir, 'cve_records.db')
    try:
        # No record yet -> curated values are kept verbatim.
        base_finding = {'cve_id': 'CVE-2011-2523', 'title': 'vsftpd 2.3.4 backdoor',
                        'severity': 'critical', 'description': 'curated', 'reference': 'curated'}
        kept = _enrich_from_official_db(dict(base_finding))
        assert kept['title'] == 'vsftpd 2.3.4 backdoor' and 'source' not in kept

        # Load an official record and confirm it overlays title/desc/ref/cvss.
        _store.upsert_records([{
            'cveMetadata': {'cveId': 'CVE-2011-2523', 'datePublished': '2011-05-01T00:00:00Z'},
            'containers': {'cna': {
                'title': 'Official vsftpd backdoor title',
                'descriptions': [{'lang': 'en', 'value': 'Official description text.'}],
                'references': [{'url': 'https://official.example/CVE-2011-2523'}],
                'metrics': [{'cvssV3_1': {'baseScore': 9.8, 'baseSeverity': 'CRITICAL',
                                          'attackVector': 'NETWORK'}}],
            }},
        }])
        enriched = _enrich_from_official_db(dict(base_finding))
        assert enriched['title'] == 'Official vsftpd backdoor title'
        assert enriched['description'] == 'Official description text.'
        assert enriched['reference'].endswith('CVE-2011-2523')
        assert enriched['cvss'] == 9.8 and enriched['source'] == 'cvelistV5'
    finally:
        _store._db_path = _orig
        _sh.rmtree(_tmpdir, ignore_errors=True)

    print('cve: OK')
    return True


if __name__ == '__main__':
    demo()
