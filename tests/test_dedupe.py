"""MAC+IP dedupe: duplicate records (legacy migration appended without dedup)
must never reach the UI, and the merge must keep the freshest data."""
from mynes.core.scanner import LANScanner


def test_dedupe_by_mac_ip_merges_and_keeps_freshest():
    dedupe = LANScanner._dedupe_by_mac_ip
    devices = [
        {'ip': '192.168.1.39', 'mac': 'B4:23:A2:4F:0F:8F', 'hostname': '',
         'alias': 'Google Smart TV', 'last_seen': '2026-08-04T16:14:22'},
        {'ip': '192.168.1.39', 'mac': 'b4:23:a2:4f:0f:8f', 'hostname': 'tv.local',
         'alias': 'Google Smart TV', 'last_seen': '2026-08-07T11:08:39'},
        {'ip': '192.168.1.42', 'mac': 'b0:d5:fb:bc:8a:6b', 'last_seen': '2026-08-07T11:08:39'},
    ]
    out = dedupe(devices)
    assert len(out) == 2                       # the .39 pair collapsed to one
    tv = next(d for d in out if d['ip'] == '192.168.1.39')
    assert tv['hostname'] == 'tv.local'        # freshest record won
    assert tv['last_seen'] == '2026-08-07T11:08:39'

    # Case-different MACs are the same key; a record with no MAC/IP is kept as-is.
    assert len(dedupe([{'note': 'a'}, {'note': 'b'}])) == 2
    # Idempotent: running twice changes nothing.
    assert dedupe(out) == out


if __name__ == '__main__':
    test_dedupe_by_mac_ip_merges_and_keeps_freshest()
    print('dedupe: OK')
