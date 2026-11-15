"""Opt-in IPv4 guest discovery; background I/O, single-writer registration."""
from collections import deque
import ipaddress
import json
import os
from pathlib import Path
import queue
import re
import subprocess
import threading
import time

from .identify import OUI_AVAILABLE, Fingerprints
from .models import Device, normalize_mac


def clean_name(value):
    return ''.join(c for c in str(value) if c.isprintable())[:80].strip()


def prepare_inventory(inventory, state_dir, simulated):
    config_path = os.environ.get('SECURIOT_DISCOVERY_CONFIG')
    if not config_path:
        return
    config = json.loads(Path(config_path).read_text())
    path = Path(state_dir) / 'discovered-devices.json'
    if not path.exists():
        return
    network = ipaddress.IPv4Network(config['cidr'])
    for row in json.loads(path.read_text()).get('devices', []):
        mac = normalize_mac(row['mac'])
        address = ipaddress.ip_address(row['ip'])
        if (address.version != 4 or address not in network or int(mac[:2], 16) & 1
                or mac == '00:00:00:00:00:00' or mac in config.get('excluded_macs', [])
                or address in (network.network_address, network.broadcast_address)):
            continue
        if inventory.get(mac) is None and not any(d.ip == str(address) for d in inventory.devices.values()):
            if len(inventory.devices) >= int(config.get('max_devices', 128)):
                break
            inventory.devices[mac] = Device(mac, str(address), clean_name(row.get('name') or 'Guest ' + mac[-8:]),
                protected=config.get('protect_guests', True), simulated=simulated,
                risk_facts={'_demo_discovered': True})


class DemoDiscovery:
    def __init__(self, config, agent, collector, cloud, iface):
        self.agent, self.collector, self.cloud = agent, collector, cloud
        self.network = ipaddress.IPv4Network(config['cidr'])
        if self.network.prefixlen < 16:
            raise ValueError('Demo discovery subnet must be /16 or smaller')
        self.iface = iface
        # With a bridged AP the neighbour table lives on the bridge, not the Wi-Fi port.
        self.neighbor_iface = config.get('neighbor_interface', iface)
        if not re.fullmatch(r'[a-zA-Z0-9_.-]{1,15}', str(self.neighbor_iface)):
            raise ValueError('neighbor_interface is not a valid interface name')
        if config['interface'] != iface:
            raise ValueError('Discovery must use the capture/AP interface')
        self.protect = config.get('protect_guests', True)
        if type(self.protect) is not bool:
            raise ValueError('protect_guests must be boolean')
        self.excluded = {normalize_mac(m) for m in config.get('excluded_macs', [])}
        try:
            self.excluded.add(normalize_mac(Path('/sys/class/net', iface, 'address').read_text().strip()))
        except OSError:
            pass
        self.leases = Path(config['leases']) if config.get('leases') else None
        self.limit = int(config.get('max_devices', 128))
        if not len(agent.inventory.devices) <= self.limit <= 1000:
            raise ValueError('max_devices must include known devices and be <= 1000')
        self.fingerprints = Fingerprints()
        if not OUI_AVAILABLE:
            print('Discovery: netaddr is not installed, so vendors cannot be read from MAC addresses (pip install netaddr).')
        self.snapshots = queue.Queue(maxsize=1)
        self.stop = threading.Event()
        self.worker = None
        self.discovered = {}
        self.path = agent.storage.directory / 'discovered-devices.json'
        for device in agent.inventory.devices.values():
            if device.risk_facts.get('_demo_discovered'):
                self.discovered[device.mac] = {'mac': device.mac, 'ip': device.ip, 'name': device.name}
        self.dirty = False
        self.last_save = 0
        # Restore discovery metadata before CloudLoop's next upload. Never restore
        # approvals from this untrusted discovery cache: use configured policy.
        if self.path.exists():
            for row in json.loads(self.path.read_text()).get('devices', []):
                try:  # saved hints are untrusted text: re-validated by Fingerprints
                    self.fingerprints.update(normalize_mac(row['mac']), hostname=row.get('hostname'),
                        vendor_class=row.get('dhcp_vendor_class'),
                        ports=row['ports'] if isinstance(row.get('ports'), list) else ())
                except (KeyError, ValueError, TypeError):
                    pass
                self.register(row['mac'], row['ip'], row.get('name'), 'saved_discovery', seen=False)
        for device in list(self.agent.inventory.devices.values()):
            if device.risk_facts.get('_demo_discovered'):
                self._identify(device)

    def start(self):
        self.worker = threading.Thread(target=self._poll, daemon=True, name='demo-discovery')
        self.worker.start()

    def _poll(self):
        while not self.stop.is_set():
            rows = []
            try:
                result = subprocess.run(['ip', '-j', '-4', 'neigh', 'show', 'dev', self.neighbor_iface],
                    capture_output=True, text=True, check=True, timeout=1)
                for row in json.loads(result.stdout):
                    states = row.get('state', [])
                    if isinstance(states, str):
                        states = states.split(',')
                    if set(states) & {'REACHABLE', 'STALE', 'DELAY', 'PROBE'}:
                        rows.append((row.get('lladdr'), row.get('dst'), None, 'neighbor_cache'))
                if self.leases:
                    for line in self.leases.read_text().splitlines():
                        parts = line.split()
                        if len(parts) >= 4:
                            try:
                                expiry = int(parts[0])
                            except ValueError:
                                continue
                            if expiry == 0 or expiry > time.time():
                                rows.append((parts[1], parts[2], None if parts[3] == '*' else parts[3], 'dhcp_lease'))
            except (OSError, subprocess.SubprocessError, ValueError) as error:
                # Surface misconfiguration without stopping local detection.
                print('Discovery poll incomplete:', type(error).__name__, str(error)[:160])
            try:
                self.snapshots.put_nowait(rows)
            except queue.Full:
                pass
            self.stop.wait(2)

    def register(self, mac, address, name, source, *, seen=False):
        try:
            mac = normalize_mac(mac)
            address = ipaddress.ip_address(address)
        except (ValueError, TypeError):
            return
        if (address.version != 4 or address not in self.network
                or address in (self.network.network_address, self.network.broadcast_address)
                or mac in self.excluded or int(mac[:2], 16) & 1
                or mac == '00:00:00:00:00:00'):
            return
        address = str(address)
        if name and source == 'dhcp_lease':
            self.fingerprints.update(mac, hostname=name)   # lease hostname is the best phone/Arduino hint
        known = self.agent.inventory.get(mac)
        # Never let a guest claim the IP of another configured/discovered MAC.
        if any(d.ip == address and d.mac != mac for d in self.agent.inventory.devices.values()):
            return
        if known is None:
            if len(self.agent.inventory.devices) >= self.limit:
                return
            protected = self.protect or (self.cloud is not None and mac in self.cloud.remote_protected)
            facts = self.fingerprints.facts(mac)
            label = facts['inferred'].get('label')
            known = Device(mac, address, clean_name(name) if name else clean_name('Guest ' + (label + ' ' if label else '') + mac[-8:]),
                           protected=protected, simulated=self.agent.enforcer.simulated)
            known.risk_facts['_demo_discovered'] = True
            known.risk_facts.update(facts)
            known.assessment = self.agent.detector.assess_device(known)
            self.agent.inventory.devices[mac] = known
            self.collector.windows[mac] = deque()
            if not self.agent.enforcer.simulated:
                self.agent.enforcer.allowed.add(mac)
            if self.protect and self.cloud is not None:
                self.cloud.local_protected.add(mac)
            self.discovered[mac] = {'mac': mac, 'ip': address, 'name': known.name, **self.fingerprints.saved(mac)}
            self.agent._event('new_device', mac, {'discovery_source': source,
                'identity_verified': False, 'name_inferred': bool(name),
                'protected': protected, 'note': 'Discovery does not establish compromise or device type',
                'inferred_type': facts['inferred'].get('type'), 'inferred_vendor': facts['inferred'].get('vendor')})
            self.dirty = True
        elif mac in self.discovered:
            # Preserve configured names and addresses. Only discovered records
            # are refreshed automatically, and names remain explicitly inferred.
            if known.ip != address:
                known.ip = address
                self.dirty = True
            if name and known.name != clean_name(name):
                known.name = clean_name(name)
                self.dirty = True
            self.discovered[mac].update(ip=known.ip, name=known.name)
            self._identify(known)
        if seen:
            known.last_seen = self.agent.clock()

    def learn(self, mac, **hints):
        """Remember what a device reveals about itself, even before its IP is known (DHCP)."""
        try:
            mac = normalize_mac(mac)
        except (ValueError, TypeError):
            return
        if mac in self.excluded or int(mac[:2], 16) & 1 or mac == '00:00:00:00:00:00':
            return
        if self.fingerprints.update(mac, **hints):
            device = self.agent.inventory.get(mac)
            if device is not None and device.risk_facts.get('_demo_discovered'):
                self._identify(device)

    def _identify(self, device):
        """Refresh inferred identity on a discovered device and re-assess it immediately."""
        facts = self.fingerprints.facts(device.mac)
        changed = False
        for key in ('inferred', 'observed_ports'):
            if device.risk_facts.get(key) != facts[key]:
                device.risk_facts[key] = facts[key]
                changed = True
        label = facts['inferred'].get('label')
        if (label and device.name.startswith('Guest ') and device.name.endswith(device.mac[-8:])
                and label not in device.name):
            device.name = clean_name(f'Guest {label} {device.mac[-8:]}')
            changed = True
        record = self.discovered.get(device.mac)
        if record is not None:
            before = dict(record)
            record.update(ip=device.ip, name=device.name, **self.fingerprints.saved(device.mac))
            self.dirty = self.dirty or record != before
        if changed:
            device.assessment = self.agent.detector.assess_device(device)
            device.snapshot_at = self.agent.clock()
        return changed

    def observe(self, record):
        if record.dhcp_hostname or record.dhcp_vendor_class or record.listening_port is not None:
            self.learn(record.source_mac, hostname=record.dhcp_hostname,
                       vendor_class=record.dhcp_vendor_class, port=record.listening_port)
        # Source only: never register an internet destination as a LAN device.
        self.register(record.source_mac, record.source_ip, None, 'captured_source', seen=True)

    def tick(self):
        try:
            rows = self.snapshots.get_nowait()
        except queue.Empty:
            rows = []
        for mac, address, name, source in rows:
            self.register(mac, address, name, source)
        if self.dirty and time.monotonic() - self.last_save >= 2:
            from .cloud_loop import atomic_json
            atomic_json(self.path, {'version': 1, 'devices': list(self.discovered.values())})
            self.dirty = False
            self.last_save = time.monotonic()

    def close(self):
        self.stop.set()
        if self.worker:
            self.worker.join(timeout=2)
        self.last_save = 0
        self.tick()
