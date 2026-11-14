"""Generate an agent-compatible inventory snapshot from Linux router data."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time


def mac(value):
    if not isinstance(value, str) or not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', value):
        raise ValueError('Invalid MAC')
    value = value.lower()
    if int(value[:2], 16) & 1 or value == '00:00:00:00:00:00':
        raise ValueError('Expected nonzero unicast MAC')
    return value


def candidates(neighbors, leases, network, now):
    """DHCP leases identify candidates; they do not prove current presence."""
    found = {}
    def add(address, hardware, source, hostname=None):
        try:
            ip = ipaddress.ip_address(address)
            hardware = mac(hardware)
        except (ValueError, TypeError):
            return
        if ip.version != 4 or ip not in network or ip in (network.network_address, network.broadcast_address):
            return
        item = found.setdefault(hardware, {'ips': set(), 'sources': set(), 'hostname': None})
        item['ips'].add(str(ip))
        item['sources'].add(source)
        if hostname and hostname != '*':
            item['hostname'] = ''.join(c for c in hostname if c.isprintable())[:100]
    for row in neighbors:
        states = row.get('state', [])
        if isinstance(states, str):
            states = states.split(',')
        if set(states) & {'REACHABLE', 'STALE', 'DELAY', 'PROBE', 'PERMANENT'}:
            add(row.get('dst'), row.get('lladdr'), 'neighbor_cache')
    for line in leases.splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        try:
            expiry = int(fields[0])
        except ValueError:
            continue
        if expiry != 0 and expiry <= now:
            continue
        add(fields[2], fields[1], 'dhcp_lease', fields[3])
    return found


def merge(base, found):
    records = base.get('devices') if isinstance(base, dict) else base
    if not isinstance(records, list):
        raise ValueError('Base inventory must be a list or {"devices": [...]}')
    result = {}
    for original in records:
        row = dict(original)
        hardware = mac(row['mac'])
        if hardware in result:
            raise ValueError('Duplicate configured MAC: ' + hardware)
        if row.get('simulated') is not False or 'persona' in row:
            raise ValueError('Use a real inventory: simulated=false and no personas')
        if type(row.get('protected', True)) is not bool:
            raise ValueError('protected must be boolean')
        row['mac'] = hardware
        row.setdefault('protected', True)
        result[hardware] = row
    evidence = []
    for hardware, item in sorted(found.items()):
        if len(item['ips']) != 1:
            raise ValueError('Multiple IPs for MAC; review before using: ' + hardware)
        address = next(iter(item['ips']))
        if hardware not in result:
            result[hardware] = {'mac': hardware, 'ip': address,
                'name': item['hostname'] or 'Unknown ' + hardware[-8:],
                'protected': True, 'simulated': False}
        else:
            result[hardware]['ip'] = address
        evidence.append({'mac': hardware, 'ip': address,
            'sources': sorted(item['sources']), 'reported_hostname': item['hostname'],
            'identity_verified': False})
    owners = {}
    for hardware, row in result.items():
        address = str(ipaddress.ip_address(row['ip']))
        if address in owners:
            raise ValueError('Conflicting IP assignment: ' + address)
        owners[address] = hardware
    return {'devices': list(result.values())}, evidence


def atomic_write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, delete=False) as stream:
            temporary = stream.name
            json.dump(value, stream, indent=2, allow_nan=False)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--interface', required=True)
    parser.add_argument('--cidr', required=True, help='IPv4 subnet of the AP')
    parser.add_argument('--leases', type=Path, help='dnsmasq lease file, if used')
    parser.add_argument('--base', type=Path, help='Reviewed real-device inventory to preserve')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    network = ipaddress.IPv4Network(args.cidr)
    neighbors = json.loads(subprocess.run(
        ['ip', '-j', '-4', 'neigh', 'show', 'dev', args.interface],
        check=True, capture_output=True, text=True, timeout=5).stdout)
    leases = args.leases.read_text() if args.leases else ''
    base = json.loads(args.base.read_text()) if args.base else []
    inventory, evidence = merge(base, candidates(neighbors, leases, network, time.time()))
    if not inventory['devices']:
        raise SystemExit('No devices found; existing output was not replaced')
    atomic_write(args.out, inventory)
    atomic_write(str(args.out) + '.discovery.json', {'observed_at': time.time(),
        'note': 'Cache/lease evidence only; not proof of identity or current presence',
        'devices': evidence})
    print(f"Saved {len(inventory['devices'])} devices to {args.out}; review before restarting the agent")


if __name__ == '__main__':
    main()
