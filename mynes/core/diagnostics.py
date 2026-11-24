"""On-demand network tools for one device: ping, traceroute, a port probe.

L0p4Map bundles nmap-backed diagnostics the user can run against any host.
MyNeS already had three-quarters of this - ``core/topology.py``'s
``trace_parent`` shells out to traceroute for uplink discovery, and
``analysis/fingerprint.py`` already connect-scans a port list - but nothing
let a user point either tool at one device on demand and see a real answer
in the UI. This module is that missing piece: thin subprocess wrappers
around the platform's own ping/traceroute binaries (no nmap requirement,
same reasoning as ``fingerprint.py``'s connect-scan: available to every
install, privileged or not), each returning parsed, structured data.

Parsing is split from the subprocess call on purpose - ``_parse_ping`` and
``_parse_traceroute`` are pure functions of captured text, tested against
literal fixtures below. Test those first; they are the cheapest layer.

    python -m mynes.core.diagnostics                 # self-check
    python -m mynes.core.diagnostics ping 192.168.1.1
    python -m mynes.core.diagnostics traceroute 192.168.1.1
"""

from __future__ import annotations

import re
import socket
import subprocess
import sys

from mynes.analysis.fingerprint import tcp_open

_TIME_RE = re.compile(r'time[=<]([\d.]+)\s*ms', re.I)
_TTL_RE = re.compile(r'ttl=(\d+)', re.I)
_HOP_IP_RE = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')
_HOP_TIME_RE = re.compile(r'([\d.]+)\s*ms')
_HOP_LINE_RE = re.compile(r'^\s*(\d+)\s+(.*)$')   # a hop line starts with its hop number


# ---------------------------------------------------------------------------
# Ping
# ---------------------------------------------------------------------------

def _parse_ping(raw: str, sent: int) -> dict:
    """Pure: ping's stdout -> structured result. Works on the Linux/macOS
    ``time=12.3 ms`` format and the Windows ``time=12ms``/``time<1ms`` one."""
    times = [float(m) for m in _TIME_RE.findall(raw or '')]
    ttl_matches = _TTL_RE.findall(raw or '')
    received = len(times)
    loss_pct = round(100.0 * (sent - received) / sent, 1) if sent else 0.0
    return {
        'success': received > 0,
        'sent': sent,
        'received': received,
        'loss_pct': loss_pct,
        'min_ms': round(min(times), 1) if times else None,
        'avg_ms': round(sum(times) / len(times), 1) if times else None,
        'max_ms': round(max(times), 1) if times else None,
        'ttl': int(ttl_matches[0]) if ttl_matches else None,
    }


def ping(ip: str, count: int = 4, timeout: float = 1.0) -> dict:
    """Runs the OS's own ``ping``. Never raises - a missing binary or a
    dead host both come back as ``success: False`` with an ``error``."""
    if sys.platform == 'win32':
        cmd = ['ping', '-n', str(count), '-w', str(int(timeout * 1000)), ip]
    else:
        cmd = ['ping', '-c', str(count), '-W', str(max(1, int(round(timeout)))), ip]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=count * timeout + 5)
    except (OSError, subprocess.SubprocessError) as exc:
        return {'success': False, 'error': str(exc), 'sent': count, 'received': 0,
                'loss_pct': 100.0, 'min_ms': None, 'avg_ms': None, 'max_ms': None,
                'ttl': None, 'raw': ''}

    result = _parse_ping(proc.stdout, count)
    result['raw'] = proc.stdout.strip()
    return result


# ---------------------------------------------------------------------------
# Traceroute
# ---------------------------------------------------------------------------

def _parse_traceroute(raw: str) -> list:
    """Pure: traceroute's/tracert's stdout -> one entry per hop line. A hop line
    is identified by its leading hop number, so the banner is skipped whether it
    lands on stdout (Windows tracert) or stderr and never reaches us (macOS/Linux
    traceroute) - a positional ``[1:]`` skip drops the first real hop in the
    latter case. A ``* * *`` hop (nothing answered) becomes ``{"timed_out": True}``."""
    hops = []
    for line in (raw or '').splitlines():
        m = _HOP_LINE_RE.match(line)
        if not m:
            continue
        hop_num, rest = int(m.group(1)), m.group(2)
        ips = _HOP_IP_RE.findall(rest)
        if not ips:
            if '*' in rest:
                hops.append({'hop': hop_num, 'ip': None, 'rtt_ms': None, 'timed_out': True})
            continue
        times = [float(t) for t in _HOP_TIME_RE.findall(rest)]
        hops.append({'hop': hop_num, 'ip': ips[0], 'rtt_ms': times[0] if times else None,
                     'timed_out': False})
    return hops


def traceroute(ip: str, max_hops: int = 15, timeout: float = 1.0) -> dict:
    """Runs the OS's own traceroute/tracert. Never raises."""
    if sys.platform == 'win32':
        cmd = ['tracert', '-d', '-h', str(max_hops), '-w', str(int(timeout * 1000)), ip]
    else:
        cmd = ['traceroute', '-n', '-q', '1', '-w', str(max(1, int(round(timeout)))),
               '-m', str(max_hops), ip]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=max_hops * (timeout + 1) + 10)
    except FileNotFoundError as exc:
        # The slim Docker image (and many minimal installs) ships no
        # traceroute binary. Fall back to sending the TTL-limited probes
        # ourselves - the container already has NET_RAW for raw ARP.
        fallback = _traceroute_raw(ip, max_hops=max_hops, timeout=timeout)
        if fallback is not None:
            return fallback
        return {'success': False, 'error': f'{exc} (and raw-socket fallback unavailable)',
                'target': ip, 'hops': [], 'raw': ''}
    except (OSError, subprocess.SubprocessError) as exc:
        return {'success': False, 'error': str(exc), 'target': ip, 'hops': [], 'raw': ''}

    hops = _parse_traceroute(proc.stdout)
    reached = bool(hops) and hops[-1].get('ip') == ip
    return {'success': bool(hops), 'target': ip, 'reached_target': reached,
            'hop_count': len(hops), 'hops': hops, 'raw': proc.stdout.strip()}


def _traceroute_raw(ip: str, max_hops: int = 15, timeout: float = 1.0) -> dict | None:
    """ICMP traceroute with scapy, for hosts without a traceroute binary.

    Returns None when it cannot run at all (no scapy, no raw-socket
    privilege) so the caller can report the original error instead.
    """
    try:
        from scapy.all import ICMP, IP, conf, sr1  # noqa: WPS433 - optional dep
    except Exception:  # noqa: BLE001
        return None
    import time

    conf.verb = 0
    hops, lines = [], []
    try:
        for ttl in range(1, max_hops + 1):
            started = time.monotonic()
            reply = sr1(IP(dst=ip, ttl=ttl) / ICMP(id=0x4d59, seq=ttl),
                        timeout=timeout, verbose=0)
            if reply is None:
                hops.append({'hop': ttl, 'ip': None, 'rtt_ms': None, 'timed_out': True})
                lines.append(f'{ttl:2d}  *')
                continue
            rtt = round((time.monotonic() - started) * 1000, 3)
            hops.append({'hop': ttl, 'ip': reply.src, 'rtt_ms': rtt, 'timed_out': False})
            lines.append(f'{ttl:2d}  {reply.src}  {rtt} ms')
            if reply.src == ip or (reply.haslayer(ICMP) and reply[ICMP].type == 0):
                break
    except PermissionError:
        return None
    except OSError as exc:
        if getattr(exc, 'errno', None) in (1, 13):   # EPERM / EACCES
            return None
        return {'success': False, 'error': str(exc), 'target': ip, 'hops': hops, 'raw': ''}

    # Trailing all-timeout hops after the last answer are noise, not a path.
    while hops and hops[-1]['timed_out'] and len(hops) > 1:
        hops.pop()
        lines.pop()
    reached = bool(hops) and hops[-1].get('ip') == ip
    return {'success': any(not h['timed_out'] for h in hops), 'target': ip,
            'reached_target': reached, 'hop_count': len(hops), 'hops': hops,
            'raw': '\n'.join(lines), 'method': 'icmp-raw'}


# ---------------------------------------------------------------------------
# Port probe / DNS - small, but the same "point it at one device" toolbox
# ---------------------------------------------------------------------------

def port_probe(ip: str, ports: list, timeout: float = 1.5) -> dict:
    """One-shot connect-scan of a user-supplied port list - "is 8080 open on
    this thing right now", without waiting for the next full scan."""
    ports = sorted({int(p) for p in ports if str(p).isdigit()})
    if not ports:
        return {'ip': ip, 'checked': [], 'open': []}
    open_ports = [p for p in ports if tcp_open(ip, p, timeout)]
    return {'ip': ip, 'checked': ports, 'open': sorted(open_ports)}


def _magic_packet(mac: str) -> bytes:
    """Pure: a MAC -> the 102-byte WOL magic packet (6x 0xFF + MAC x16)."""
    hexmac = re.sub(r'[^0-9a-fA-F]', '', mac)
    if len(hexmac) != 12:
        raise ValueError(f'invalid MAC for WOL: {mac!r}')
    return b'\xff' * 6 + bytes.fromhex(hexmac) * 16


def wake_on_lan(mac: str, broadcast: str = '255.255.255.255', port: int = 9) -> dict:
    """Send a Wake-on-LAN magic packet. Never raises - a bad MAC or a dead
    socket comes back as ``success: False`` with an ``error``. The device must
    have WOL enabled in its BIOS/OS for this to actually wake it."""
    try:
        packet = _magic_packet(mac)
    except ValueError as exc:
        return {'success': False, 'mac': mac, 'error': str(exc)}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.sendto(packet, (broadcast, port))
        return {'success': True, 'mac': mac, 'broadcast': broadcast, 'port': port}
    except OSError as exc:
        return {'success': False, 'mac': mac, 'error': str(exc)}


def _reverse_name(ip: str) -> str:
    return '.'.join(reversed(ip.split('.'))) + '.in-addr.arpa'


def _mdns_ptr_query(ip: str) -> bytes:
    """Pure: a one-question DNS packet asking PTR for ``ip``'s reverse name."""
    import struct
    qname = b''.join(bytes([len(label)]) + label.encode('ascii')
                     for label in _reverse_name(ip).split('.')) + b'\x00'
    # id=0, flags=0, 1 question; QTYPE=PTR(12), QCLASS=IN with the QU bit.
    return struct.pack('>HHHHHH', 0, 0, 1, 0, 0, 0) + qname + struct.pack('>HH', 12, 0x8001)


def _dns_read_name(buf: bytes, offset: int) -> tuple[str, int]:
    """Pure: decode a (possibly compressed) DNS name; returns (name, next offset)."""
    labels, jumped, end, hops = [], False, offset, 0
    while True:
        if offset >= len(buf) or hops > 64:
            raise ValueError('truncated name')
        length = buf[offset]
        if length & 0xC0 == 0xC0:
            pointer = ((length & 0x3F) << 8) | buf[offset + 1]
            if not jumped:
                end = offset + 2
            offset, jumped, hops = pointer, True, hops + 1
            continue
        if length == 0:
            if not jumped:
                end = offset + 1
            return '.'.join(labels), end
        labels.append(buf[offset + 1:offset + 1 + length].decode('utf-8', 'replace'))
        offset += 1 + length


def _parse_ptr_answer(buf: bytes, ip: str) -> str | None:
    """Pure: the PTR target for ``ip`` in a DNS/mDNS response, else None."""
    import struct
    if len(buf) < 12:
        return None
    qd, an, ns, ar = struct.unpack('>HHHH', buf[4:12])
    offset = 12
    try:
        for _ in range(qd):
            _, offset = _dns_read_name(buf, offset)
            offset += 4
        want = _reverse_name(ip).lower()
        for _ in range(an + ns + ar):
            name, offset = _dns_read_name(buf, offset)
            rtype, _cls, _ttl, rdlen = struct.unpack('>HHIH', buf[offset:offset + 10])
            offset += 10
            if rtype == 12 and name.lower() == want:
                target, _ = _dns_read_name(buf, offset)
                return target.rstrip('.') or None
            offset += rdlen
    except (ValueError, struct.error, IndexError):
        return None
    return None


def mdns_reverse(ip: str, timeout: float = 1.5) -> str | None:
    """Ask the device itself (and the mDNS group) for its .local name.

    Home routers rarely serve PTR records for DHCP clients, so a plain
    reverse lookup fails for nearly every LAN device - but anything that
    speaks Bonjour/Avahi (Apple, Linux, printers, Chromecasts, many IoT
    boxes) answers this. Sent from an ephemeral port, so responders reply
    by unicast (RFC 6762 s6.7) and no 5353 bind is needed.
    """
    import time
    packet = _mdns_ptr_query(ip)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
            sock.settimeout(0.3)
            for dest in ((ip, 5353), ('224.0.0.251', 5353)):
                try:
                    sock.sendto(packet, dest)
                except OSError:
                    pass
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                try:
                    raw, _ = sock.recvfrom(4096)
                except socket.timeout:
                    continue
                name = _parse_ptr_answer(raw, ip)
                if name:
                    return name
    except OSError:
        return None
    return None


def dns_lookup(ip: str, timeout: float = 3.0) -> dict:
    """Name lookup for one IP, on demand - the periodic scan already tries
    this once, but a user watching a device's name change wants a retry
    button, not another full scan.

    Tries unicast reverse DNS, then mDNS, then NetBIOS: a LAN router usually
    has no PTR record for a DHCP client, so DNS alone came back empty for
    nearly every device and the tool looked broken."""
    previous = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    dns_error = None
    try:
        hostname, aliases, _ = socket.gethostbyaddr(ip)
        return {'ip': ip, 'success': True, 'hostname': hostname, 'aliases': aliases,
                'source': 'dns'}
    except (socket.herror, socket.gaierror, OSError) as exc:
        dns_error = str(exc)
    finally:
        socket.setdefaulttimeout(previous)

    name = mdns_reverse(ip)
    if name:
        return {'ip': ip, 'success': True, 'hostname': name, 'aliases': [], 'source': 'mdns'}

    try:
        from mynes.analysis.fingerprint import smb_probe
        nb = smb_probe(ip, timeout=1.5)
    except Exception:  # noqa: BLE001
        nb = None
    if nb and nb.get('netbios_name'):
        aliases = [nb['workgroup']] if nb.get('workgroup') else []
        return {'ip': ip, 'success': True, 'hostname': nb['netbios_name'],
                'aliases': aliases, 'source': 'netbios'}

    return {'ip': ip, 'success': False, 'hostname': None,
            'error': f'no DNS PTR ({dns_error}), no mDNS or NetBIOS answer',
            'source': None}


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------

def demo():
    """Parsers only - no subprocess, no network, so this runs anywhere."""
    linux_ping = (
        "PING 192.168.1.1 (192.168.1.1) 56(84) bytes of data.\n"
        "64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=1.23 ms\n"
        "64 bytes from 192.168.1.1: icmp_seq=2 ttl=64 time=0.98 ms\n"
        "\n--- 192.168.1.1 ping statistics ---\n"
        "2 packets transmitted, 2 received, 0% packet loss, time 1001ms\n"
    )
    parsed = _parse_ping(linux_ping, sent=2)
    assert parsed['success'] is True
    assert parsed['received'] == 2 and parsed['loss_pct'] == 0.0
    assert parsed['ttl'] == 64
    assert parsed['min_ms'] == 1.0 and parsed['max_ms'] == 1.2   # rounded to 1 decimal

    # A dead host: nothing answered, not an exception.
    dead = _parse_ping("PING 10.9.9.9 (10.9.9.9) 56(84) bytes of data.\n"
                       "\n--- 10.9.9.9 ping statistics ---\n"
                       "3 packets transmitted, 0 received, 100% packet loss\n", sent=3)
    assert dead['success'] is False and dead['received'] == 0 and dead['loss_pct'] == 100.0

    # Windows format: "time=12ms" / "time<1ms", no decimal point.
    windows_ping = ("Reply from 192.168.1.1: bytes=32 time=12ms TTL=128\n"
                    "Reply from 192.168.1.1: bytes=32 time<1ms TTL=128\n")
    parsed_win = _parse_ping(windows_ping, sent=2)
    assert parsed_win['received'] == 2 and parsed_win['ttl'] == 128

    linux_trace = (
        "traceroute to 192.168.1.10 (192.168.1.10), 5 hops max\n"
        " 1  192.168.1.1  0.512 ms\n"
        " 2  * * *\n"
        " 3  192.168.1.10  1.204 ms\n"
    )
    hops = _parse_traceroute(linux_trace)
    assert len(hops) == 3
    assert hops[0] == {'hop': 1, 'ip': '192.168.1.1', 'rtt_ms': 0.512, 'timed_out': False}
    assert hops[1] == {'hop': 2, 'ip': None, 'rtt_ms': None, 'timed_out': True}
    assert hops[2]['ip'] == '192.168.1.10'

    # Real macOS/Linux traceroute puts the banner on stderr, so stdout is hop
    # lines only. The first hop must survive (a positional skip ate it before).
    no_banner = " 1  192.168.1.1  1.917 ms\n 2  10.45.128.1  4.935 ms\n"
    hops2 = _parse_traceroute(no_banner)
    assert len(hops2) == 2 and hops2[0]['ip'] == '192.168.1.1' and hops2[0]['hop'] == 1

    # One-hop route to the gateway: a single line, still a reachable hop.
    hops3 = _parse_traceroute(" 1  192.168.1.1  1.403 ms\n")
    assert hops3 == [{'hop': 1, 'ip': '192.168.1.1', 'rtt_ms': 1.403, 'timed_out': False}]

    # A port probe against nothing listening: never raises, empty open list.
    result = port_probe('192.0.2.1', [65535], timeout=0.05)
    assert result['checked'] == [65535] and result['open'] == []

    # Garbage port values are dropped rather than raising.
    assert port_probe('192.0.2.1', ['not-a-port', 80], timeout=0.01)['checked'] == [80]

    # WOL magic packet: 6 bytes of 0xFF then the MAC repeated 16 times, and any
    # separator style parses. A bad MAC is a clean failure, not an exception.
    pkt = _magic_packet('01:02:03:04:05:06')
    assert len(pkt) == 102 and pkt[:6] == b'\xff' * 6
    assert pkt[6:12] == bytes.fromhex('010203040506')
    assert _magic_packet('01-02-03-04-05-06') == pkt == _magic_packet('010203040506')
    assert wake_on_lan('nonsense')['success'] is False

    # mDNS PTR round-trip: build a query, hand-craft the answer a responder
    # would send (name compressed against the question), parse it back.
    import struct
    q = _mdns_ptr_query('192.168.1.42')
    assert q[12:].startswith(b'\x0242\x011\x03168\x03192\x07in-addr\x04arpa\x00')
    target = b'\x07macbook\x05local\x00'
    answer = (struct.pack('>HHHHHH', 0, 0x8400, 1, 1, 0, 0) + q[12:]
              + b'\xc0\x0c' + struct.pack('>HHIH', 12, 0x8001, 120, len(target)) + target)
    assert _parse_ptr_answer(answer, '192.168.1.42') == 'macbook.local'
    assert _parse_ptr_answer(answer, '192.168.1.43') is None
    assert _parse_ptr_answer(b'\x00' * 5, '192.168.1.42') is None

    print('diagnostics: OK')
    return True


if __name__ == '__main__':
    if len(sys.argv) > 2 and sys.argv[1] == 'ping':
        import json
        print(json.dumps(ping(sys.argv[2]), indent=2))
    elif len(sys.argv) > 2 and sys.argv[1] == 'traceroute':
        import json
        print(json.dumps(traceroute(sys.argv[2]), indent=2))
    elif len(sys.argv) > 2 and sys.argv[1] == 'wol':
        import json
        print(json.dumps(wake_on_lan(sys.argv[2]), indent=2))
    else:
        demo()
