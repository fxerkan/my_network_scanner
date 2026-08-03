#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Active service fingerprinting.

The previous classifier guessed a device's type from open port *numbers*
alone, which is how a Raspberry Pi running SSH and a web app came back as
"Router". Port numbers are a weak signal: everything on a LAN serves HTTP.

This module asks the services what they are instead:

* an RTSP ``OPTIONS`` handshake that answers ``RTSP/1.0`` proves a camera,
  whatever port it listens on,
* an HTTP ``Server`` header, ``WWW-Authenticate`` realm or ``<title>`` names
  the firmware ("Hikvision", "DiskStation", "Tapo"),
* an SSH banner names the OS ("Raspbian", "Ubuntu", "dropbear"),
* being the default gateway is the *only* strong evidence of a router.

Everything here is stdlib. ``classify()`` and ``suggest_name()`` are pure
functions of a signal dict - test those first, they are the cheapest layer.

Run directly for a self-check:  python -m mynes.analysis.fingerprint
Or against a host:              python -m mynes.analysis.fingerprint 192.168.1.78
"""

import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor

# ---------------------------------------------------------------------------
# Ports
# ---------------------------------------------------------------------------

# Knocked on for every device. Kept short enough that a /24 stays fast.
BASE_PORTS = (
    21, 22, 23, 25, 53, 80, 139, 443, 445, 515, 631,
    1883, 3389, 5000, 5001, 5900, 8000, 8008, 8080, 8443, 9100,
)

# Camera makers scatter RTSP and ONVIF across non-standard ports. Without
# these in the sweep an RTSP camera is invisible - it may have no other port
# open at all.
CAMERA_PORTS = (554, 2020, 8554, 8899, 10554, 34567, 37777)

SCAN_PORTS = tuple(sorted(set(BASE_PORTS + CAMERA_PORTS)))

# Ports where an RTSP handshake is worth attempting.
RTSP_PORTS = (554, 8554, 10554, 2020, 8000, 88)

# Ports that speak HTTP(S). The bool is "wrap in TLS".
HTTP_PORTS = ((80, False), (8080, False), (8000, False), (443, True), (8443, True), (5000, False))

# 0.7s was too short: the RTSP cameras on this LAN needed ~1s to accept a
# connection and were reported as having no open ports at all.
CONNECT_TIMEOUT = 1.5
READ_TIMEOUT = 2.5

# ---------------------------------------------------------------------------
# Vendor / banner vocabularies
# ---------------------------------------------------------------------------

CAMERA_HINTS = (
    'hikvision', 'dahua', 'reolink', 'wansview', 'wanscam', 'foscam', 'amcrest',
    'axis', 'vivotek', 'uniview', 'annke', 'lorex', 'swann', 'tapo', 'ezviz',
    'onvif', 'ipcam', 'ip camera', 'netcam', 'webcam', 'nvr', 'dvr', 'doorbell',
    'imou', 'sricam', 'yi home', 'tp-link camera', 'goke', 'xiongmai',
)

PRINTER_HINTS = ('printer', 'jetdirect', 'laserjet', 'officejet', 'deskjet',
                 'ecosys', 'imageclass', 'brother', 'cups', 'ipp')

NAS_HINTS = ('synology', 'diskstation', 'qnap', 'truenas', 'freenas', 'unraid',
             'openmediavault', 'terramaster', 'asustor', 'wd my cloud')

ROUTER_HINTS = ('router', 'gateway', 'openwrt', 'dd-wrt', 'mikrotik', 'routeros',
                'pfsense', 'opnsense', 'edgerouter', 'unifi', 'draytek', 'fritz!box',
                'airport', 'keenetic', 'modem', 'web-based configurator',
                'configurator', 'wireless ap', 'access point')

ROUTER_VENDORS = ('mikrotik', 'ubiquiti', 'tp-link', 'zyxel', 'asustek', 'netgear',
                  'draytek', 'keenetic', 'avm gmbh', 'arris', 'technicolor',
                  'sagemcom', 'huawei technologies', 'zte', 'd-link', 'tenda')

TV_HINTS = ('smart tv', 'webos', 'tizen', 'bravia', 'android tv', 'roku',
            'chromecast', 'firetv', 'fire tv', 'appletv', 'apple tv', 'shield')

IOT_VENDORS = ('espressif', 'tuya', 'shelly', 'sonoff', 'itead', 'xiaomi',
               'shenzhen', 'tasmota', 'aqara', 'lifx', 'signify', 'philips lighting',
               'nanoleaf', 'sonos', 'ikea of sweden', 'amazon technologies',
               'google', 'roborock', 'ecovacs', 'dyson')

MOBILE_VENDORS = ('samsung electronics', 'oneplus', 'xiaomi communications',
                  'xiaomi mobile', 'beijing xiaomi', 'oppo', 'vivo mobile',
                  'realme', 'motorola mobility', 'huawei device', 'honor device')

# OUI lookups return these when the block is private, unassigned or held by a
# registry. They name nobody, so they must not end up in a device's name.
JUNK_VENDORS = ('unknown', 'bilinmeyen', 'private', 'ieee registration authority',
                'ieee registration', 'unassigned', 'n/a', 'locally administered')


SERVICE_NAMES = {
    21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'domain', 80: 'http',
    88: 'kerberos', 139: 'netbios-ssn', 443: 'https', 445: 'microsoft-ds',
    515: 'printer', 554: 'rtsp', 631: 'ipp', 1883: 'mqtt', 2020: 'onvif',
    3389: 'ms-wbt-server', 5000: 'upnp-http', 5001: 'commplex-link',
    5900: 'vnc', 8000: 'http-alt', 8008: 'http-alt', 8080: 'http-proxy',
    8443: 'https-alt', 8554: 'rtsp-alt', 8899: 'ovnif-alt', 9100: 'jetdirect',
    10554: 'rtsp-alt', 34567: 'dvr', 37777: 'dvr',
}


def service_name(port):
    """Best-effort service label for a port number."""
    return SERVICE_NAMES.get(int(port), 'unknown')


def _has(text, needles):
    """True if any needle appears in text. Both are lowercased by the caller."""
    return any(n in text for n in needles)


# ---------------------------------------------------------------------------
# Probes - each returns a plain dict / None and never raises
# ---------------------------------------------------------------------------

def tcp_open(ip, port, timeout=CONNECT_TIMEOUT):
    """One TCP connect. No nmap, no root."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def scan_tcp(ip, ports=SCAN_PORTS, timeout=CONNECT_TIMEOUT, workers=24):
    """Connect-scan a port list. Returns the open ones, sorted."""
    ports = list(ports)
    with ThreadPoolExecutor(max_workers=min(workers, len(ports) or 1)) as pool:
        results = pool.map(lambda p: (p, tcp_open(ip, p, timeout)), ports)
        return sorted(p for p, is_open in results if is_open)


def rtsp_options(ip, port, timeout=READ_TIMEOUT):
    """Speak RTSP. A device that answers ``RTSP/1.0`` is a camera or an NVR.

    Works without credentials: 401 Unauthorized is still an RTSP answer, and
    the ``Server``/``WWW-Authenticate`` headers usually name the vendor.
    """
    request = (
        f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\n"
        "CSeq: 1\r\n"
        "User-Agent: MyNeS\r\n\r\n"
    ).encode()
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(request)
            raw = sock.recv(2048).decode('utf-8', 'replace')
    except OSError:
        return None

    if not raw.startswith('RTSP/'):
        return None

    head = raw.split('\r\n\r\n', 1)[0]
    headers = {}
    for line in head.split('\r\n')[1:]:
        if ':' in line:
            key, _, value = line.partition(':')
            headers[key.strip().lower()] = value.strip()

    return {
        'port': port,
        'status': raw.split(' ')[1] if ' ' in raw else '',
        'server': headers.get('server', ''),
        'public': headers.get('public', ''),
        'realm': _realm(headers.get('www-authenticate', '')),
        'url': f"rtsp://{ip}:{port}/",
    }


def rtsp_probe(ip, ports=RTSP_PORTS, open_ports=None):
    """First RTSP responder wins. Skips ports already known to be closed."""
    candidates = [p for p in ports if open_ports is None or p in open_ports]
    for port in candidates:
        found = rtsp_options(ip, port)
        if found:
            return found
    return None


_TITLE_RE = re.compile(r'<title[^>]*>(.*?)</title>', re.I | re.S)
_REALM_RE = re.compile(r'realm="([^"]*)"', re.I)


def _realm(header_value):
    match = _REALM_RE.search(header_value or '')
    return match.group(1) if match else ''


def http_banner(ip, port, tls=False, timeout=READ_TIMEOUT):
    """GET / and keep only what identifies the box: Server, auth realm, title."""
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except OSError:
        return None
    try:
        sock.settimeout(timeout)
        if tls:
            context = ssl._create_unverified_context()
            sock = context.wrap_socket(sock, server_hostname=ip)
        sock.sendall(
            f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: MyNeS\r\n"
            "Accept: */*\r\nConnection: close\r\n\r\n".encode()
        )
        chunks, total = [], 0
        while total < 16384:
            try:
                chunk = sock.recv(4096)
            except (socket.timeout, ssl.SSLError, OSError):
                break
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        raw = b''.join(chunks).decode('utf-8', 'replace')
    except (OSError, ssl.SSLError):
        return None
    finally:
        try:
            sock.close()
        except OSError:
            pass

    if not raw:
        return None

    head, _, body = raw.partition('\r\n\r\n')
    headers = {}
    for line in head.split('\r\n')[1:]:
        if ':' in line:
            key, _, value = line.partition(':')
            headers[key.strip().lower()] = value.strip()

    title_match = _TITLE_RE.search(body)
    return {
        'port': port,
        'tls': tls,
        'status': head.split(' ')[1] if ' ' in head else '',
        'server': headers.get('server', ''),
        'realm': _realm(headers.get('www-authenticate', '')),
        'title': ' '.join(title_match.group(1).split())[:120] if title_match else '',
        'powered_by': headers.get('x-powered-by', ''),
    }


def ssh_banner(ip, port=22, timeout=READ_TIMEOUT):
    """SSH servers greet first: ``SSH-2.0-OpenSSH_8.4p1 Raspbian-5+deb11u3``."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            line = sock.recv(256).decode('utf-8', 'replace').strip()
    except OSError:
        return None
    return line if line.startswith('SSH-') else None


def gather(ip, open_ports=None, vendor='', hostname='', is_gateway=False,
           deep=True):
    """Collect every signal we can get about one host.

    ``open_ports`` may be pre-supplied (from an earlier nmap pass) to skip the
    connect scan. Returns the dict that ``classify()`` consumes.
    """
    if open_ports is None:
        open_ports = scan_tcp(ip)
    else:
        open_ports = sorted({int(p) for p in open_ports})

    signals = {
        'ip': ip,
        'open_ports': open_ports,
        'vendor': vendor or '',
        'hostname': hostname or '',
        'is_gateway': bool(is_gateway),
        'rtsp': None,
        'http': [],
        'ssh': None,
    }
    if not deep:
        return signals

    signals['rtsp'] = rtsp_probe(ip, open_ports=open_ports)

    for port, tls in HTTP_PORTS:
        if port in open_ports:
            banner = http_banner(ip, port, tls)
            if banner:
                signals['http'].append(banner)

    if 22 in open_ports:
        signals['ssh'] = ssh_banner(ip)

    return signals


# ---------------------------------------------------------------------------
# Classification - pure, no I/O, test this first
# ---------------------------------------------------------------------------

def _corpus(signals):
    """Every piece of text we know about the device, lowercased, in one blob."""
    parts = [signals.get('hostname', ''), signals.get('vendor', ''),
             signals.get('ssh') or '']
    rtsp = signals.get('rtsp') or {}
    parts += [rtsp.get('server', ''), rtsp.get('realm', '')]
    onvif = signals.get('onvif') or {}
    parts += [onvif.get('name') or '', onvif.get('model') or '',
              onvif.get('vendor') or '']
    for banner in signals.get('http') or []:
        parts += [banner.get('server', ''), banner.get('title', ''),
                  banner.get('realm', ''), banner.get('powered_by', '')]
    return ' '.join(p for p in parts if p).lower()


def classify(signals):
    """Signals -> {'device_type', 'confidence', 'reasons'}.

    Ordered strongest evidence first. A rule only fires on evidence that
    actually distinguishes - "port 80 is open" distinguishes nothing.
    """
    ports = set(signals.get('open_ports') or [])
    text = _corpus(signals)
    vendor = (signals.get('vendor') or '').lower()
    hostname = (signals.get('hostname') or '').lower()

    def verdict(device_type, confidence, reason):
        return {'device_type': device_type, 'confidence': confidence,
                'reasons': [reason]}

    # 1. The default gateway is a router. This is the only signal that really
    #    proves it - "SSH plus a web page" never did.
    if signals.get('is_gateway'):
        return verdict('Router', 0.99, 'default gateway')

    # 2. It answered an ONVIF probe, or it answered RTSP. Nothing but a
    #    camera or an NVR does either.
    if signals.get('onvif'):
        model = (signals['onvif'] or {}).get('model') or ''
        return verdict('IP Camera', 0.98,
                       'ONVIF' + (f' ({model})' if model else ''))

    if signals.get('rtsp'):
        server = signals['rtsp'].get('server') or signals['rtsp'].get('realm') or ''
        return verdict('IP Camera', 0.97,
                       f"RTSP on port {signals['rtsp']['port']}"
                       + (f" ({server})" if server else ''))

    # 3. Camera firmware named itself over HTTP, or an ONVIF port is open.
    if _has(text, CAMERA_HINTS):
        return verdict('IP Camera', 0.93, 'camera firmware in banner')
    if ports & {8899, 34567, 37777} or (2020 in ports and 554 in ports):
        return verdict('IP Camera', 0.85, 'camera/NVR control port open')

    if _has(text, PRINTER_HINTS) or ports & {9100, 631, 515}:
        return verdict('Printer', 0.92, 'printing service')

    if 'airtunes' in text or 'airplay' in text:
        return verdict('Apple Device', 0.90, 'AirPlay service')

    if _has(text, NAS_HINTS):
        return verdict('NAS', 0.92, 'NAS firmware in banner')

    # 4. A Raspberry Pi is a small Linux computer, never a router. Vendor OUI
    #    and the SSH banner both say so plainly.
    if 'raspberry' in vendor or 'raspberry' in text or 'raspbian' in text:
        if 22 in ports:
            return verdict('Raspberry Pi Server', 0.94, 'Raspberry Pi with SSH')
        return verdict('IoT Device', 0.80, 'Raspberry Pi board')

    # 5. Routers: named as one, or a router vendor that also runs DNS/DHCP.
    if _has(hostname, ROUTER_HINTS) or _has(text, ROUTER_HINTS):
        return verdict('Router', 0.88, 'router firmware or hostname')
    if _has(vendor, ROUTER_VENDORS) and 53 in ports:
        return verdict('Router', 0.80, 'router vendor serving DNS')

    if _has(text, TV_HINTS) or ports & {8008, 8009, 7000, 8001, 8002}:
        return verdict('Smart TV', 0.78, 'TV or casting service')

    if 1883 in ports or 8883 in ports:
        return verdict('Server', 0.75, 'MQTT broker')

    # 6. Operating system, from the SSH greeting or the RDP/SMB pair.
    ssh = (signals.get('ssh') or '').lower()
    if 3389 in ports:
        return verdict('Desktop', 0.82, 'RDP')
    if ssh:
        if 'ubuntu' in ssh or 'debian' in ssh or 'openssh' in ssh:
            if ports & {80, 443, 8080, 8443}:
                return verdict('Server', 0.72, 'Linux SSH plus a web service')
            return verdict('Server', 0.65, 'Linux SSH')
        if 'dropbear' in ssh:
            return verdict('IoT Device', 0.70, 'embedded SSH (dropbear)')

    if 'apple' in vendor:
        return verdict('Apple Device', 0.70, 'Apple OUI')
    if _has(vendor, MOBILE_VENDORS):
        return verdict('Smartphone', 0.60, 'mobile vendor OUI')
    if _has(vendor, IOT_VENDORS):
        return verdict('IoT Device', 0.65, 'IoT vendor OUI')

    if 445 in ports or 139 in ports:
        return verdict('Desktop', 0.55, 'SMB')

    # A network-gear brand with nothing but a web port, on a LAN whose router
    # we already found, is smart-home kit - a plug, a bulb, an extender.
    if _has(vendor, ROUTER_VENDORS) and ports and ports <= {80, 443, 8080, 8443}:
        return verdict('IoT Device', 0.55, 'network-brand device with only a web UI')

    return {'device_type': 'Unknown', 'confidence': 0.0, 'reasons': []}


# ---------------------------------------------------------------------------
# Naming - pure
# ---------------------------------------------------------------------------

_NOISE = re.compile(r'\.(local|lan|home|localdomain)\.?$', re.I)
_GENERIC_TITLES = {'', 'index', 'home', 'login', 'welcome', 'document',
                   'untitled', 'web client', 'index of /', 'sign in', 'dashboard'}

# Words that mark a page title as a *page* title. A real gateway answers with
# ".::Welcome to the Web-Based Configurator::." - decoration, not a device name.
# Self-hosted apps announce themselves in <title>. "qBittorrent WebUI" is a
# service running on the device - the device is still a Raspberry Pi.
APP_TITLES = ('qbittorrent', 'transmission', 'deluge', 'sonarr', 'radarr',
              'portainer', 'grafana', 'prometheus', 'jellyfin', 'plex', 'emby',
              'home assistant', 'pi-hole', 'pihole', 'nextcloud', 'jenkins',
              'gitea', 'nginx', 'apache', 'traefik', 'uptime kuma', 'adguard',
              'octoprint', 'node-red', 'proxmox', 'cockpit', 'webmin', 'unifi')

_TITLE_STOPWORDS = ('welcome', 'configurator', 'log in', 'login', 'sign in',
                    '管理', 'admin panel', 'control panel', 'setup wizard',
                    'please', 'error', 'not found', 'forbidden', 'unauthorized')

# Leading/trailing decoration some firmwares wrap their title in.
_DECORATION = re.compile(r'^[\s\.:\-=_*|>#\[\]]+|[\s\.:\-=_*|<#\[\]]+$')

# A vendor field is a legal entity name; a device name is not.
_VENDOR_NOISE = re.compile(
    r'\b(inc|inc\.|corp|corp\.|corporation|co|co\.|ltd|ltd\.|limited|gmbh|'
    r'llc|s\.a\.|sa|bv|b\.v\.|ag|plc|technologies|technology|electronics|'
    r'international|company|holdings|group|trading|communications|communication|'
    r'systems|solutions|networks|network|devices|device|industries|'
    r'information|informationtech|semiconductor)\b', re.I)


def clean_vendor(vendor, max_words=2):
    """"Raspberry Pi Trading Ltd" -> "Raspberry Pi".

    Returns '' for registry placeholders like "IEEE Registration Authority" -
    a name built from those is worse than no name.
    """
    raw = (vendor or '').strip()
    if not raw or _has(raw.lower(), JUNK_VENDORS):
        return ''
    name = _VENDOR_NOISE.sub('', raw)
    name = re.sub(r'[,\.]+', ' ', name)
    words = name.split()
    # "Beijing Roborock Technology Co Ltd" -> "Beijing Roborock". A brand needs
    # two words at most; the rest is corporate filing.
    return ' '.join(words[:max_words])


def suggest_name(signals, device_type='Unknown'):
    """Best human-readable name we can derive, in descending trustworthiness.

    Returns '' when nothing beats the IP address - the caller decides whether
    to fall back, and an empty string never overwrites a name the user set.
    """
    # A camera's ONVIF scope carries the name its owner configured.
    onvif = signals.get('onvif') or {}
    if onvif.get('name'):
        return str(onvif['name']).strip()

    hostname = (signals.get('hostname') or '').strip()
    if hostname and not _is_ipish(hostname):
        return _NOISE.sub('', hostname).strip('.') or hostname

    # A camera's RTSP or HTTP realm is usually its configured device name.
    rtsp = signals.get('rtsp') or {}
    if rtsp.get('realm') and not _is_generic(rtsp['realm']):
        return rtsp['realm'].strip()

    for banner in signals.get('http') or []:
        title = title_as_name(banner.get('title'))
        if title:
            return title
        realm = (banner.get('realm') or '').strip()
        if realm and not _is_generic(realm):
            return realm

    vendor = clean_vendor(signals.get('vendor'))
    last_octet = (signals.get('ip') or '').rsplit('.', 1)[-1]
    if vendor and device_type not in ('Unknown', ''):
        # "Raspberry Pi" + "Raspberry Pi Server" must not stutter.
        if vendor.lower() in device_type.lower():
            return f"{device_type} {last_octet}".strip()
        return f"{vendor} {device_type}".strip()
    if vendor:
        return f"{vendor} {last_octet}".strip()
    if device_type not in ('Unknown', ''):
        return f"{device_type} {last_octet}".strip()
    return ''


def title_as_name(title):
    """A page <title> that is genuinely a device name, or '' if it is prose.

    Cameras and NAS boxes put their configured name in the title, which is the
    best name we can get. Routers put a sentence there, which is the worst.
    """
    text = _DECORATION.sub('', (title or '').strip())
    if not text or len(text) > 32 or _is_ipish(text):
        return ''
    lowered = text.lower()
    if lowered in _GENERIC_TITLES or _has(lowered, _TITLE_STOPWORDS):
        return ''
    if _has(lowered, APP_TITLES):
        return ''
    if len(text.split()) > 4:          # a sentence, not a label
        return ''
    return text


def _is_ipish(text):
    return bool(re.fullmatch(r'[\d\.:]+', text or ''))


def _is_generic(text):
    return (text or '').strip().lower() in _GENERIC_TITLES | {'ipcamera', 'camera',
                                                              'device', 'admin'}


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------

def demo():
    """Asserts the rules that were actually wrong in the field."""

    # The bug this module exists for: a Pi with SSH and a web app was "Router".
    pi = {'ip': '192.168.1.62', 'open_ports': [22, 8080],
          'vendor': 'Raspberry Pi Trading Ltd', 'hostname': '',
          'is_gateway': False, 'rtsp': None, 'http': [], 'ssh': None}
    assert classify(pi)['device_type'] == 'Raspberry Pi Server', classify(pi)

    # Same ports, but it *is* the gateway -> router. Position, not ports.
    gw = dict(pi, vendor='Zyxel Communications', is_gateway=True)
    assert classify(gw)['device_type'] == 'Router'

    # An RTSP answer beats everything else, including a camera on port 2020.
    cam = {'ip': '192.168.1.78', 'open_ports': [554], 'vendor': 'Shenzhen Foo',
           'hostname': '', 'is_gateway': False, 'ssh': None, 'http': [],
           'rtsp': {'port': 554, 'server': 'Wansview/1.0', 'realm': 'Q3',
                    'status': '401', 'public': '', 'url': 'rtsp://192.168.1.78:554/'}}
    result = classify(cam)
    assert result['device_type'] == 'IP Camera' and result['confidence'] > 0.9

    # A camera that only shows a web UI is still a camera.
    web_cam = {'ip': '192.168.1.79', 'open_ports': [80], 'vendor': '', 'hostname': '',
               'is_gateway': False, 'ssh': None, 'rtsp': None,
               'http': [{'port': 80, 'server': 'Hikvision-Webs', 'title': '',
                         'realm': '', 'powered_by': '', 'tls': False, 'status': '200'}]}
    assert classify(web_cam)['device_type'] == 'IP Camera'

    # Printers win on port alone - 9100 is not ambiguous.
    printer = dict(pi, vendor='Brother', open_ports=[80, 515, 9100])
    assert classify(printer)['device_type'] == 'Printer'

    # Nothing to go on stays Unknown rather than guessing "Router".
    blank = dict(pi, vendor='', open_ports=[80])
    assert classify(blank)['device_type'] == 'Unknown', classify(blank)

    # Naming: hostname wins, then the camera's own realm, then vendor + type.
    assert suggest_name({'hostname': 'octopi.local', 'ip': '192.168.1.62'}) == 'octopi'
    assert suggest_name(cam, 'IP Camera') == 'Q3'
    assert suggest_name(pi, 'Raspberry Pi Server') == 'Raspberry Pi Server 62'
    assert clean_vendor('Raspberry Pi Trading Ltd') == 'Raspberry Pi'
    assert clean_vendor('Google, Inc.') == 'Google'

    # A generic page title must not become the device name.
    generic = {'ip': '192.168.1.9', 'hostname': '', 'vendor': 'Acme Inc',
               'http': [{'title': 'Login', 'realm': '', 'server': ''}]}
    assert suggest_name(generic, 'Server') == 'Acme Server'

    # The real Zyxel gateway on this LAN. Its title is prose and must not
    # become the device's name; the router hint must still classify it.
    zyxel_title = '.::Welcome to the Web-Based Configurator::.'
    assert title_as_name(zyxel_title) == '', title_as_name(zyxel_title)
    zyxel = {'ip': '192.168.1.1', 'open_ports': [53, 80, 443], 'vendor': 'Zyxel',
             'hostname': '', 'is_gateway': False, 'ssh': None, 'rtsp': None,
             'http': [{'title': zyxel_title, 'server': '', 'realm': '',
                       'powered_by': '', 'port': 80, 'tls': False, 'status': '200'}]}
    assert classify(zyxel)['device_type'] == 'Router', classify(zyxel)
    assert suggest_name(zyxel, 'Router') == 'Zyxel Router'

    # A NAS puts its actual name in the title - that one we keep.
    assert title_as_name('DiskStation') == 'DiskStation'
    assert title_as_name('QNAP Turbo NAS TS-453') == 'QNAP Turbo NAS TS-453'

    # A camera that answered the ONVIF probe is named by its owner, not by us.
    onvif_cam = {'ip': '192.168.1.147', 'open_ports': [443, 554, 2020],
                 'vendor': '', 'hostname': '', 'is_gateway': False,
                 'ssh': None, 'http': [], 'rtsp': None,
                 'onvif': {'name': 'C212', 'model': 'C212', 'vendor': ''}}
    assert classify(onvif_cam)['device_type'] == 'IP Camera'
    assert suggest_name(onvif_cam, 'IP Camera') == 'C212'

    # The app running on a Pi is not the Pi's name.
    assert title_as_name('qBittorrent WebUI') == ''
    pi_web = dict(pi, http=[{'title': 'qBittorrent WebUI', 'server': '',
                             'realm': '', 'powered_by': ''}])
    assert suggest_name(pi_web, 'Raspberry Pi Server') == 'Raspberry Pi Server 62'
    assert clean_vendor('Zyxel Communications Corporation') == 'Zyxel'

    # This Mac answered 22/445/5000/5900 and was called a NAS.
    mac_host = {'ip': '192.168.1.135', 'open_ports': [22, 445, 5000, 5900],
                'vendor': '', 'hostname': '', 'is_gateway': False, 'rtsp': None,
                'ssh': None, 'http': [{'port': 5000, 'server': 'AirTunes/870.14.1',
                                       'title': '', 'realm': '', 'powered_by': ''}]}
    assert classify(mac_host)['device_type'] == 'Apple Device', classify(mac_host)

    # Four TP-Link boxes with a bare web port were all called "Router" while
    # the actual router sat at .1. A LAN has one router: the gateway.
    plug = {'ip': '192.168.1.75', 'open_ports': [80], 'vendor': 'TP-Link Systems Inc',
            'hostname': '', 'is_gateway': False, 'rtsp': None, 'ssh': None,
            'http': [{'port': 80, 'server': '', 'title': '', 'realm': '',
                      'powered_by': ''}]}
    assert classify(plug)['device_type'] == 'IoT Device', classify(plug)

    # Registry placeholders are not vendors and must not become names.
    assert clean_vendor('IEEE Registration Authority') == ''
    assert clean_vendor('Unknown') == ''
    assert clean_vendor('Beijing Roborock Technology Co., Ltd.') == 'Beijing Roborock'
    nameless = {'ip': '192.168.1.57', 'hostname': '', 'vendor': 'Unknown',
                'http': [], 'open_ports': []}
    assert suggest_name(nameless, 'Unknown') == '', suggest_name(nameless, 'Unknown')

    # A Xiaomi phone is a phone, not a smart bulb.
    phone = {'ip': '192.168.1.185', 'open_ports': [], 'hostname': '',
             'vendor': 'Beijing Xiaomi Mobile Software Co., Ltd',
             'is_gateway': False, 'rtsp': None, 'http': [], 'ssh': None}
    assert classify(phone)['device_type'] == 'Smartphone', classify(phone)

    print('fingerprint: OK')
    return True


if __name__ == '__main__':
    import sys

    if len(sys.argv) > 1:
        target = sys.argv[1]
        print(f'Probing {target} ...')
        found = gather(target)
        for key, value in found.items():
            print(f'  {key}: {value}')
        print('  ->', classify(found))
        print('  name:', suggest_name(found, classify(found)['device_type']))
    else:
        demo()
