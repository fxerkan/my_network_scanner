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
    except (OSError, subprocess.SubprocessError) as exc:
        return {'success': False, 'error': str(exc), 'target': ip, 'hops': [], 'raw': ''}

    hops = _parse_traceroute(proc.stdout)
    reached = bool(hops) and hops[-1].get('ip') == ip
    return {'success': bool(hops), 'target': ip, 'reached_target': reached,
            'hop_count': len(hops), 'hops': hops, 'raw': proc.stdout.strip()}


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


def dns_lookup(ip: str, timeout: float = 3.0) -> dict:
    """Reverse DNS for one IP, on demand - the periodic scan already tries
    this once, but a user watching a device's name change wants a retry
    button, not another full scan."""
    previous = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        hostname, aliases, _ = socket.gethostbyaddr(ip)
        return {'ip': ip, 'success': True, 'hostname': hostname, 'aliases': aliases}
    except (socket.herror, socket.gaierror, OSError) as exc:
        return {'ip': ip, 'success': False, 'hostname': None, 'error': str(exc)}
    finally:
        socket.setdefaulttimeout(previous)


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
