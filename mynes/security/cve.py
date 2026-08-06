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

import re

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
        'reference': 'https://nvd.nist.gov/vuln/detail/CVE-2011-2523',
    },
    {
        'id': 'CVE-2015-3306', 'title': 'ProFTPD mod_copy unauthenticated file copy', 'severity': 'high',
        'match': {'ftp': r'proftpd\s*1\.3\.5'},
        'description': 'ProFTPD 1.3.5 with mod_copy enabled lets an unauthenticated client copy '
                       'files anywhere the FTP process can write, which is a path to remote code '
                       'execution. Verify mod_copy is disabled or the server is patched.',
        'reference': 'https://nvd.nist.gov/vuln/detail/CVE-2015-3306',
    },
    {
        'id': 'CVE-2021-41773', 'title': 'Apache HTTP Server 2.4.49 path traversal', 'severity': 'critical',
        'match': {'http': r'apache/2\.4\.49\b'},
        'description': 'Apache 2.4.49 allows path traversal to read files outside the document '
                       'root, and to RCE when CGI/mod_cgi is enabled (CVE-2021-42013 patched the '
                       'same class again in 2.4.50). Upgrade to 2.4.51 or later.',
        'reference': 'https://nvd.nist.gov/vuln/detail/CVE-2021-41773',
    },
    {
        'id': 'CVE-2021-42013', 'title': 'Apache HTTP Server 2.4.50 path traversal/RCE', 'severity': 'critical',
        'match': {'http': r'apache/2\.4\.50\b'},
        'description': "The fix for CVE-2021-41773 in 2.4.50 was incomplete - this build is "
                       "still exploitable the same way. Upgrade to 2.4.51 or later.",
        'reference': 'https://nvd.nist.gov/vuln/detail/CVE-2021-42013',
    },
    {
        'id': 'CVE-2017-7921', 'title': 'Hikvision camera authentication bypass', 'severity': 'high',
        'match': {'http': r'hikvision', 'rtsp': r'hikvision'},
        'match_any': True,
        'description': 'Older Hikvision camera/NVR firmware has had multiple authentication-'
                       'bypass and credential-disclosure vulnerabilities (CVE-2017-7921 and '
                       'related). This only proves the device *is* Hikvision gear, not its '
                       'firmware version - check for a firmware update from Hikvision.',
        'reference': 'https://nvd.nist.gov/vuln/detail/CVE-2017-7921',
    },
    {
        'id': 'CVE-2021-33044', 'title': 'Dahua camera authentication bypass', 'severity': 'high',
        'match': {'http': r'dahua', 'rtsp': r'dahua'}, 'match_any': True,
        'description': 'Dahua and Dahua-derived (OEM) camera/NVR firmware has had authentication-'
                       'bypass vulnerabilities (CVE-2021-33044/33045). This only proves the '
                       'device is Dahua-family gear, not its firmware version - check for an '
                       'update.',
        'reference': 'https://nvd.nist.gov/vuln/detail/CVE-2021-33044',
    },
    {
        'id': 'CVE-2018-9995', 'title': 'Generic TBK-derived DVR/NVR credential disclosure', 'severity': 'high',
        'match': {}, 'ports': {34567, 37777},
        'description': 'Ports 34567/37777 are the proprietary control ports used by TBK-derived '
                       'DVR/NVR firmware (sold under many brand names). This firmware family has '
                       'had credential-disclosure and unauthenticated-RCE vulnerabilities '
                       '(CVE-2018-9995 and others). Verify the firmware is current and the port '
                       'is not reachable from outside the LAN.',
        'reference': 'https://nvd.nist.gov/vuln/detail/CVE-2018-9995',
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


def match_cves(signals: dict, open_ports: set) -> list:
    """-> every ``CVE_PATTERNS`` entry whose conditions are all satisfied."""
    findings = []
    for pattern in CVE_PATTERNS:
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
        findings.append({
            'cve_id': pattern['id'], 'title': pattern['title'], 'severity': pattern['severity'],
            'description': pattern['description'], 'reference': pattern['reference'],
        })
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


def risk_level(score: int, findings: list | None = None) -> str:
    """A single critical-severity CVE match (a real backdoor, a known RCE)
    means the device *is* critical, even if nothing else about it scores
    high enough to reach the number on its own - severity should not get
    diluted away by averaging against an otherwise quiet fingerprint."""
    severities = {f['severity'] for f in (findings or [])}
    if 'critical' in severities or score >= 70:
        return 'critical'
    if 'high' in severities or score >= 40:
        return 'high'
    if score >= 15:
        return 'medium'
    if score > 0:
        return 'low'
    return 'none'


def assess_device(device: dict) -> dict:
    """Everything the Security tab needs for one device, built entirely
    from data a normal scan already collected - no new network I/O."""
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
        'ip': device.get('ip'), 'risk_score': score, 'risk_level': risk_level(score, findings),
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

    # Telnet open is a "high" exposure with no CVE attached.
    telnet_host = {'ip': '192.168.1.55', 'fingerprint': {}, 'open_ports': [{'port': 23}]}
    result = assess_device(telnet_host)
    assert result['exposures'][0]['title'] == 'Telnet is open'
    assert result['exposures'][0]['severity'] == 'high'

    # risk_level thresholds are monotonic and match the documented buckets.
    assert risk_level(0) == 'none'
    assert risk_level(10) == 'low'
    assert risk_level(20) == 'medium'
    assert risk_level(45) == 'high'
    assert risk_level(80) == 'critical'
    # ...and a single critical finding forces "critical" even at a low score.
    assert risk_level(5, [{'severity': 'critical'}]) == 'critical'

    # A fleet summary sorts the worst device first.
    summary = fleet_summary([clean, backdoored_ftp, telnet_host])
    assert summary['devices'][0]['ip'] == '192.168.1.50'
    assert summary['at_risk_count'] == 2

    print('cve: OK')
    return True


if __name__ == '__main__':
    demo()
