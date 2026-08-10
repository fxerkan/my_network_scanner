"""What a device's operating system and network medium probably are.

Three copies of banner-string OS guessing already existed, scattered across
``scanner.py._os_detection`` (nmap ``-sV`` output only), ``advanced.py``'s TTL
bucketing, and ``enhanced.py``'s service-hint cascade - none of them saw what
the others saw, so a Windows box that only proved itself over SMB and a Linux
box that only proved itself over SSH were guessed with unrelated, duplicated
logic. This module is the one place that looks at *everything*
``fingerprint.gather()`` already collected - SSH/FTP banners, HTTP Server
headers, NetBIOS/SMB, and a TTL if the caller has one - and reasons about OS
family and (best-effort) whether a device is more likely on WiFi or wired.

Nothing here does I/O. Both functions are pure: signal dict in, verdict out.
No nmap ``-O`` (needs raw sockets, which is exactly the privilege problem
``core/arp.py`` already works around) - this stays available to every
install, privileged or not.

    python -m mynes.analysis.os_detect      # self-check
"""

from __future__ import annotations

import re

# TTL buckets. A packet loses one hop per router; home-LAN devices are
# almost always one hop away, so the observed TTL is close to the OS
# default. Values are the common initial TTLs, highest (most restrictive)
# match wins so a real answer of e.g. 63 (64 - 1 hop) still buckets as Linux.
_TTL_DEFAULTS = (
    (64, 'Linux/Unix'),      # Linux, most BSDs, macOS, Android, most IoT/RTOS
    (128, 'Windows'),        # Windows, and some routers configured to mimic it
    (255, 'Cisco IOS/Network Gear'),
)

_LINUX_HINTS = ('ubuntu', 'debian', 'raspbian', 'fedora', 'centos', 'rhel',
                'alpine', 'arch linux', 'openwrt', 'dd-wrt', 'busybox', 'dropbear',
                'linux')
_WINDOWS_HINTS = ('windows', 'microsoft', 'iis', 'microsoft-iis', 'win32')
_MAC_HINTS = ('darwin', 'macos', 'mac os x', 'airtunes', 'apple')
_BSD_HINTS = ('freebsd', 'openbsd', 'netbsd', 'pfsense', 'opnsense', 'truenas')
_NETWORK_OS_HINTS = ('cisco ios', 'routeros', 'junos', 'fortios', 'ios-xe')

# Windows/Samba answering NBNS at all is itself strong evidence - almost
# nothing else implements NetBIOS name service in 2026.
_WINDOWS_WORKGROUP_DEFAULTS = ('workgroup', 'mshome')

# Last-resort OS priors when no banner named the OS. A vendor OUI or a settled
# device type is a weak but real signal: a Samsung TV runs Tizen, a robot
# vacuum runs embedded Linux, an ESP chip runs an RTOS. Always low confidence -
# these are priors, never measurements. Vendor match is tried before type.
_VENDOR_OS = (
    ('espressif', 'Linux/Unix', 'RTOS (ESP-IDF)'),
    ('roborock', 'Linux/Unix', 'Embedded Linux'),
    ('ecovacs', 'Linux/Unix', 'Embedded Linux'),
    ('dreame', 'Linux/Unix', 'Embedded Linux'),
    ('roku', 'Linux/Unix', 'Roku OS'),
    ('mxchip', 'Linux/Unix', 'Embedded RTOS'),
)
# (device_type substring, vendor substring or '' for any) -> (family, detail).
_TYPE_OS = (
    ('smart tv', 'samsung', 'Linux/Unix', 'Tizen'),
    ('smart tv', 'lg', 'Linux/Unix', 'webOS'),
    ('smart tv', '', 'Linux/Unix', 'Android TV / embedded'),
    ('ip camera', '', 'Linux/Unix', 'Embedded Linux'),
    ('robot vacuum', '', 'Linux/Unix', 'Embedded Linux'),
    ('router', '', 'Linux/Unix', 'Embedded Linux'),
    ('printer', '', 'Linux/Unix', 'Embedded'),
    ('esp device', '', 'Linux/Unix', 'RTOS (ESP-IDF)'),
    ('smart appliance', '', 'Linux/Unix', 'Embedded'),
)


def _vendor_type_os(signals, device_type):
    """Weak OS prior from vendor OUI / settled device type, or None."""
    vendor = (signals.get('vendor') or '').lower()
    dtype = (device_type or '').lower()
    for needle, family, detail in _VENDOR_OS:
        if needle in vendor:
            return _verdict(family, detail, 0.4, [f'{needle} vendor default OS'])
    for dneedle, vneedle, family, detail in _TYPE_OS:
        if dneedle in dtype and (not vneedle or vneedle in vendor):
            reason = f'{device_type} default OS' + (f' ({vneedle})' if vneedle else '')
            return _verdict(family, detail, 0.35, [reason])
    return None


def _ttl_bucket(ttl):
    if ttl is None:
        return None
    for ceiling, name in _TTL_DEFAULTS:
        if ttl <= ceiling:
            return name
    return None


def guess_os(signals: dict, ttl: int | None = None, device_type: str = '') -> dict:
    """-> ``{"os_family", "detail", "confidence", "reasons"}``.

    ``os_family`` is one of "Linux/Unix", "Windows", "macOS", "BSD",
    "Network Gear", or "Unknown". Ordered strongest evidence first: a
    service that names its own OS in a banner beats a TTL guess, which is
    just an initial value every stack of a kind shares. ``device_type`` (when
    already classified) sharpens the last-resort prior - a Samsung Smart TV
    runs Tizen, a camera runs embedded Linux - so a banner-silent device is
    still labelled instead of left "Unknown".
    """
    reasons = []

    ssh = (signals.get('ssh') or '').lower()
    if ssh:
        if 'raspbian' in ssh or 'ubuntu' in ssh or 'debian' in ssh:
            return _verdict('Linux/Unix', ssh, 0.9, [f'SSH banner: {signals["ssh"]}'])
        if 'dropbear' in ssh:
            return _verdict('Linux/Unix', 'Embedded Linux (dropbear)', 0.75,
                            [f'SSH banner: {signals["ssh"]}'])
        if 'openssh' in ssh:
            reasons.append(f'SSH banner: {signals["ssh"]}')
            # OpenSSH itself runs everywhere - keep looking, but note it.

    smb = signals.get('smb') or {}
    if smb:
        workgroup = (smb.get('workgroup') or '').lower()
        detail = smb.get('netbios_name') or 'SMB/NetBIOS host'
        confidence = 0.75 if workgroup in _WINDOWS_WORKGROUP_DEFAULTS else 0.65
        return _verdict('Windows', detail, confidence,
                        reasons + [f'NetBIOS name service answered ({detail})'])

    ftp = (signals.get('ftp') or '').lower()
    if ftp:
        if 'microsoft ftp' in ftp:
            return _verdict('Windows', signals['ftp'], 0.85, [f'FTP banner: {signals["ftp"]}'])
        if any(h in ftp for h in ('vsftpd', 'proftpd', 'pure-ftpd')):
            return _verdict('Linux/Unix', signals['ftp'], 0.7, [f'FTP banner: {signals["ftp"]}'])

    for banner in signals.get('http') or []:
        text = ' '.join([banner.get('server', ''), banner.get('powered_by', '')]).lower()
        if not text.strip():
            continue
        if _has(text, _WINDOWS_HINTS):
            return _verdict('Windows', banner.get('server') or banner.get('powered_by'),
                            0.75, [f'HTTP Server: {text.strip()}'])
        if _has(text, _MAC_HINTS):
            return _verdict('macOS', banner.get('server'), 0.7, [f'HTTP Server: {text.strip()}'])
        if _has(text, _BSD_HINTS):
            return _verdict('BSD', banner.get('server'), 0.7, [f'HTTP Server: {text.strip()}'])
        if _has(text, _NETWORK_OS_HINTS):
            return _verdict('Network Gear', banner.get('server'), 0.75,
                            [f'HTTP Server: {text.strip()}'])
        if _has(text, _LINUX_HINTS):
            return _verdict('Linux/Unix', banner.get('server'), 0.65,
                            [f'HTTP Server: {text.strip()}'])

    if ssh:
        # A bare "OpenSSH" banner names no OS, but it does rule out Windows
        # (its native SSH server, added in 10, still says "OpenSSH_for_Windows").
        if 'for_windows' in ssh:
            return _verdict('Windows', signals['ssh'], 0.7, reasons)
        return _verdict('Linux/Unix', signals['ssh'], 0.55, reasons or ['generic OpenSSH banner'])

    bucket = _ttl_bucket(ttl)
    if bucket:
        return _verdict(bucket, f'TTL {ttl}', 0.35, [f'observed TTL {ttl}'])

    prior = _vendor_type_os(signals, device_type)
    if prior:
        return prior

    return {'os_family': 'Unknown', 'detail': '', 'confidence': 0.0, 'reasons': []}


def _verdict(family, detail, confidence, reasons):
    return {'os_family': family, 'detail': (detail or '').strip(),
            'confidence': confidence, 'reasons': reasons}


def _has(text, needles):
    return any(n in text for n in needles)


# ---------------------------------------------------------------------------
# Connection medium (WiFi vs wired) - always a guess, never claimed as fact
# ---------------------------------------------------------------------------

# Device types that are overwhelmingly battery/radio-first hardware on a
# home LAN. A desktop can have a WiFi card and a phone can be docked, so this
# is a prior, not a certainty - callers must treat it as advisory.
_WIFI_LEANING_TYPES = (
    'smartphone', 'tablet', 'laptop', 'smart tv', 'smart speaker', 'smart bulb',
    'smart plug', 'iot device', 'smart home', 'wearable', 'game console',
    'media player', 'ip camera', 'robot vacuum', 'apple device',
)
_WIRED_LEANING_TYPES = (
    'router', 'switch', 'modem', 'gateway', 'access point', 'nas', 'server',
    'printer', 'desktop', 'raspberry pi server', 'docker container',
)

_MOBILE_RADIO_VENDOR_HINTS = ('espressif', 'tuya', 'shelly', 'sonoff', 'xiaomi',
                              'apple', 'samsung electronics', 'huawei device',
                              'amazon technologies', 'google', 'sonos')


def guess_connection_medium(device_type: str = '', vendor: str = '',
                            signals: dict | None = None) -> dict:
    """-> ``{"medium": "wifi"|"wired"|"unknown", "confidence", "reasons"}``.

    There is no way to see which physical medium a remote host used to reach
    the switch without polling the AP's or switch's own client table (not
    implemented - it needs router-specific credentials this app does not
    have). This is a prior built from what the device *is*, not a
    measurement, and is always reported with a confidence low enough that
    the UI must label it a guess.
    """
    signals = signals or {}
    dtype = (device_type or '').lower()
    vendor_l = (vendor or '').lower()
    reasons = []

    if signals.get('is_gateway') or dtype in ('router', 'modem', 'gateway'):
        return {'medium': 'wired', 'confidence': 0.9, 'reasons': ['is the gateway/router']}

    for wired_type in _WIRED_LEANING_TYPES:
        if wired_type in dtype:
            return {'medium': 'wired', 'confidence': 0.6,
                    'reasons': [f'device type "{device_type}" is usually wired']}

    for wifi_type in _WIFI_LEANING_TYPES:
        if wifi_type in dtype:
            reasons.append(f'device type "{device_type}" is usually WiFi-only')
            confidence = 0.55
            if _has(vendor_l, _MOBILE_RADIO_VENDOR_HINTS):
                confidence = 0.65
                reasons.append(f'vendor "{vendor}" makes radio-first hardware')
            return {'medium': 'wifi', 'confidence': confidence, 'reasons': reasons}

    if 3389 in (signals.get('open_ports') or []) or 445 in (signals.get('open_ports') or []):
        return {'medium': 'wired', 'confidence': 0.4,
                'reasons': ['RDP/SMB open - usually a desk-bound machine']}

    return {'medium': 'unknown', 'confidence': 0.0, 'reasons': []}


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------

def demo():
    # A Raspberry Pi's own SSH banner names its OS outright.
    pi_signals = {'ssh': 'SSH-2.0-OpenSSH_8.4p1 Raspbian-5+deb11u3', 'smb': None,
                  'ftp': None, 'http': []}
    verdict = guess_os(pi_signals)
    assert verdict['os_family'] == 'Linux/Unix' and verdict['confidence'] >= 0.8, verdict

    # SMB/NetBIOS answering at all outranks a generic OpenSSH banner - nothing
    # but Windows/Samba implements NBNS, and Samba boxes are rare on a
    # consumer LAN compared to actual Windows PCs.
    win_signals = {'ssh': None, 'ftp': None, 'http': [],
                   'smb': {'netbios_name': 'FAMILY-PC', 'workgroup': 'WORKGROUP'}}
    verdict = guess_os(win_signals)
    assert verdict['os_family'] == 'Windows', verdict
    assert verdict['confidence'] > 0.7, verdict

    # An HTTP Server header naming IIS is Windows even with nothing else.
    iis_signals = {'ssh': None, 'ftp': None, 'smb': None,
                   'http': [{'server': 'Microsoft-IIS/10.0', 'powered_by': ''}]}
    assert guess_os(iis_signals)['os_family'] == 'Windows'

    # Nothing but a TTL: a weak, low-confidence bucket guess, never claimed
    # as strong evidence.
    ttl_only = {'ssh': None, 'ftp': None, 'smb': None, 'http': []}
    verdict = guess_os(ttl_only, ttl=61)
    assert verdict['os_family'] == 'Linux/Unix' and verdict['confidence'] < 0.5, verdict
    verdict = guess_os(ttl_only, ttl=126)
    assert verdict['os_family'] == 'Windows'

    # Nothing at all: Unknown, not a wrong guess.
    assert guess_os({})['os_family'] == 'Unknown'

    # A vsftpd banner is Linux; a Microsoft FTP Service banner is Windows.
    assert guess_os({'ftp': '220 (vsFTPd 3.0.3)', 'ssh': None, 'smb': None,
                     'http': []})['os_family'] == 'Linux/Unix'
    assert guess_os({'ftp': '220 Microsoft FTP Service', 'ssh': None, 'smb': None,
                     'http': []})['os_family'] == 'Windows'

    # Banner-silent devices still get a low-confidence prior from vendor/type
    # instead of a bare "Unknown": a Samsung Smart TV runs Tizen, a camera runs
    # embedded Linux, an Espressif chip runs an RTOS.
    tv = guess_os({'vendor': 'Samsung Electronics'}, device_type='Smart TV')
    assert tv['os_family'] == 'Linux/Unix' and tv['detail'] == 'Tizen', tv
    assert tv['confidence'] < 0.5
    cam = guess_os({'vendor': 'Sichuan AI-Link'}, device_type='IP Camera')
    assert cam['detail'] == 'Embedded Linux', cam
    esp = guess_os({'vendor': 'Espressif Inc.'}, device_type='IoT Device')
    assert esp['detail'] == 'RTOS (ESP-IDF)', esp
    # A real banner still beats the prior.
    assert guess_os({'ssh': 'SSH-2.0-OpenSSH_8.4p1 Raspbian'},
                    device_type='IP Camera')['detail'] != 'Embedded Linux'
    # Nothing to go on, no type: honestly Unknown.
    assert guess_os({})['os_family'] == 'Unknown'

    # Connection medium: the gateway is always wired.
    gw = guess_connection_medium('Router', 'Zyxel', {'is_gateway': True})
    assert gw['medium'] == 'wired' and gw['confidence'] > 0.8

    # A phone is a WiFi-leaning device type by default.
    phone = guess_connection_medium('Smartphone', 'Apple, Inc.')
    assert phone['medium'] == 'wifi'

    # A NAS is wired-leaning.
    nas = guess_connection_medium('NAS', 'Synology')
    assert nas['medium'] == 'wired'

    # An unclassified device with nothing to go on stays honestly unknown.
    unknown = guess_connection_medium('Unknown', '')
    assert unknown['medium'] == 'unknown' and unknown['confidence'] == 0.0

    print('os_detect: OK')
    return True


if __name__ == '__main__':
    demo()
