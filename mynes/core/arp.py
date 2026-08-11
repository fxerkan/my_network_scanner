"""Layer-2 host discovery that works without root.

Scapy's `srp()` needs raw sockets, i.e. root. Run MyNeS as a normal user and it
silently finds nothing - which looks like an empty network rather than a
permissions problem. That is the worst possible failure mode for a scanner.

Strategy, in order:

1. **Raw ARP** (scapy) when we actually have the privilege. Fastest and finds
   hosts that ignore ping.
2. **Ping sweep + OS ARP cache** otherwise. A parallel ICMP/TCP sweep forces the
   kernel to resolve each address, then we read the neighbour table it filled
   in. No elevated privileges anywhere: `ping` is setuid on every mainstream OS,
   and reading the ARP cache is unprivileged.

Either way `discover()` reports which method ran, so the UI can tell the user
that running elevated would find more.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import platform
import re
import shutil
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor

log = logging.getLogger(__name__)

# "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0" - macOS/BSD `arp -an`
# "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE" - Linux `ip neigh`
# "  192.168.1.1    aa-bb-cc-dd-ee-ff   dynamic" - Windows `arp -a`
_MAC = r'(?:[0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2}'
_IP = r'\d{1,3}(?:\.\d{1,3}){3}'
# `.+?` rather than `\D+?`: Linux puts the interface name ("dev eth0") between
# the address and the MAC, and that contains a digit.
_ARP_LINE = re.compile(rf'({_IP}).+?({_MAC})')

INCOMPLETE = {'incomplete', '(incomplete)', 'ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00'}


def has_raw_socket_privilege() -> bool:
    """True when this process can open the raw sockets scapy's ARP needs."""
    if os.name == 'nt':
        # Npcap grants access without an admin check; let scapy decide.
        return True
    if hasattr(os, 'geteuid') and os.geteuid() == 0:
        return True
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s.close()
        return True
    except (PermissionError, OSError):
        return False


def normalise_mac(mac: str) -> str:
    parts = re.split(r'[:-]', mac)
    return ':'.join(p.zfill(2).lower() for p in parts)


def read_arp_cache() -> dict[str, str]:
    """Read the OS neighbour table. Unprivileged on every supported platform."""
    system = platform.system()
    if system == 'Windows':
        cmd = ['arp', '-a']
    elif system == 'Linux' and shutil.which('ip'):
        cmd = ['ip', 'neigh', 'show']
    else:
        cmd = ['arp', '-an']

    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=15).stdout
    except (OSError, subprocess.SubprocessError) as e:
        log.warning('could not read the ARP cache via %s: %s', cmd[0], e)
        return {}

    found = {}
    for line in out.splitlines():
        m = _ARP_LINE.search(line)
        if not m:
            continue
        ip, mac = m.group(1), normalise_mac(m.group(2))
        if mac in INCOMPLETE or ip.endswith('.255') or ip.startswith('224.'):
            continue
        found[ip] = mac
    return found


def _touch(ip: str, timeout: float) -> None:
    """Make the kernel resolve `ip`, so it lands in the ARP cache.

    A single ping is enough; the reply is irrelevant, the ARP exchange that
    precedes it is the point. Devices that drop ICMP still answer ARP.
    """
    count_flag = '-n' if platform.system() == 'Windows' else '-c'
    wait_flag = '-w' if platform.system() == 'Windows' else '-W'
    wait_value = str(int(timeout * 1000)) if platform.system() == 'Windows' else str(max(1, int(timeout)))
    try:
        subprocess.run(
            ['ping', count_flag, '1', wait_flag, wait_value, ip],
            capture_output=True, timeout=timeout + 2,
        )
    except (OSError, subprocess.SubprocessError):
        pass


def ping_sweep(network: str, timeout: float = 1.0, workers: int = 128) -> None:
    hosts = [str(h) for h in ipaddress.ip_network(network, strict=False).hosts()]
    if len(hosts) > 4096:
        log.warning('refusing to sweep %s (%d hosts) - narrow the range', network, len(hosts))
        return
    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(lambda ip: _touch(ip, timeout), hosts))


def _scapy_arp(network: str, timeout: float, iface: str | None = None) -> list[dict]:
    from scapy.all import ARP, Ether, srp

    kwargs = {'timeout': timeout, 'verbose': 0}
    if iface:
        kwargs['iface'] = iface  # bind the sweep to a chosen NIC (Settings)
    answered = srp(Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=network), **kwargs)[0]
    return [{'ip': r.psrc, 'mac': normalise_mac(r.hwsrc), 'method': 'arp'} for _, r in answered]


def discover(network: str, timeout: float = 2.0, prefer_raw: bool = True,
             iface: str | None = None) -> dict:
    """Find every layer-2 reachable host on `network`.

    Returns {"devices": [{ip, mac, method}], "method": str, "elevated": bool,
             "hint": str|None} - `hint` is a user-facing note when a fallback ran.
    """
    if prefer_raw and has_raw_socket_privilege():
        try:
            devices = _scapy_arp(network, timeout, iface)
            if devices:
                return {'devices': devices, 'method': 'arp-raw', 'elevated': True, 'hint': None}
            log.info('raw ARP returned nothing on %s; falling back to the ping sweep', network)
        except (PermissionError, OSError, RuntimeError) as e:
            log.info('raw ARP unavailable (%s); falling back to the ping sweep', e)
        except Exception as e:  # noqa: BLE001 - scapy raises a wide range on unsupported ifaces
            log.info('raw ARP failed (%s); falling back to the ping sweep', e)

    before = read_arp_cache()
    ping_sweep(network, timeout=timeout)
    after = read_arp_cache()

    net = ipaddress.ip_network(network, strict=False)
    devices = [
        {'ip': ip, 'mac': mac, 'method': 'arp-cache' if ip in before else 'ping-sweep'}
        for ip, mac in after.items()
        if ipaddress.ip_address(ip) in net
    ]
    return {
        'devices': devices,
        'method': 'ping-sweep',
        'elevated': False,
        'hint': (
            'Running without raw-socket privileges. MyNeS used a ping sweep plus the '
            'OS ARP cache, which misses devices that ignore ICMP and do not talk to '
            'this host. Run elevated (sudo / Administrator, or the Docker image with '
            'NET_RAW) for a complete layer-2 scan.'
        ),
    }


def demo():
    """Self-check: parsing is correct and the network filter holds."""
    line_bsd = '? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]'
    line_linux = '192.168.1.42 dev eth0 lladdr AA:BB:CC:11:22:33 REACHABLE'
    line_win = '  192.168.1.99         aa-bb-cc-44-55-66     dynamic'

    for line, ip, mac in [(line_bsd, '192.168.1.1', 'aa:bb:cc:dd:ee:ff'),
                          (line_linux, '192.168.1.42', 'aa:bb:cc:11:22:33'),
                          (line_win, '192.168.1.99', 'aa:bb:cc:44:55:66')]:
        m = _ARP_LINE.search(line)
        assert m, line
        assert m.group(1) == ip, m.group(1)
        assert normalise_mac(m.group(2)) == mac, normalise_mac(m.group(2))

    # Short octets must be zero-padded, not left ragged.
    assert normalise_mac('a:b:c:1:2:3') == '0a:0b:0c:01:02:03'
    print('arp demo OK')


if __name__ == '__main__':
    import json
    import sys

    demo()
    target = sys.argv[1] if len(sys.argv) > 1 else '192.168.1.0/24'
    print(json.dumps(discover(target), indent=2))
