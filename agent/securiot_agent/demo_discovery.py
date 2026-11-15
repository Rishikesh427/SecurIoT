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
    # A station must stay unassociated this long before it is shown offline, so a
    # quick Wi-Fi reconnect or roam does not flicker the dashboard.
    OFFLINE_AFTER = 15

    def __init__(self, config, agent, collector, cloud, iface):
        self.agent, self.collector, self.cloud = agent, collector, cloud
        self.network = ipaddress.IPv4Network(config['cidr'])
        if self.network.prefixlen < 16:
            raise ValueError('Demo discovery subnet must be /16 or smaller')
        self.iface = iface
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
        self.absent_since = {}
        self.station_error_shown = False
        # Restore discovery metadata before CloudLoop's next upload. Never restore
        # approvals from this untrusted discovery cache: use configured policy.
        if self.path.exists():
            for row in json.loads(self.path.read_text()).get('devices', []):
                self.register(row['mac'], row['ip'], row.get('name'), 'saved_discovery', seen=False)
        # Uploads require last_seen, so a device that left before a restart could
        # never be reported offline unless its last packet time survives restarts.
        self.presence_path = agent.storage.directory / 'presence.json'
        self.presence_saved = 0
        self._restore_last_seen()

    def _restore_last_seen(self):
        saved = {}
        if self.presence_path.exists():
            try:
                saved = json.loads(self.presence_path.read_text()).get('last_seen', {})
            except (OSError, ValueError):
                saved = {}
        legacy = self.path.stat().st_mtime if self.path.exists() else None
        for device in self.agent.inventory.devices.values():
            if device.last_seen is not None:
                continue
            if isinstance(saved.get(device.mac), (int, float)):
                device.last_seen = float(saved[device.mac])
            elif legacy is not None and device.mac in self.discovered:
                # Saved before last-seen times were kept: the discovery file's
                # last write is the best available estimate.
                device.last_seen = legacy

    def _save_presence(self):
        from .cloud_loop import atomic_json
        atomic_json(self.presence_path, {'version': 1, 'last_seen': {
            d.mac: d.last_seen for d in self.agent.inventory.devices.values() if d.last_seen is not None}})
        self.presence_saved = time.monotonic()

    def start(self):
        self.worker = threading.Thread(target=self._poll, daemon=True, name='demo-discovery')
        self.worker.start()

    def _poll(self):
        while not self.stop.is_set():
            rows = []
            try:
                result = subprocess.run(['ip', '-j', '-4', 'neigh', 'show', 'dev', self.iface],
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
                self.snapshots.put_nowait((rows, self._stations()))
            except queue.Full:
                pass
            self.stop.wait(2)

    def _stations(self):
        """Currently associated Wi-Fi clients, or None when presence is unknown."""
        try:
            result = subprocess.run(['iw', 'dev', self.iface, 'station', 'dump'],
                capture_output=True, text=True, check=True, timeout=1)
            return {normalize_mac(m) for m in re.findall(r'^Station\s+([0-9a-fA-F:]{17})', result.stdout, re.M)}
        except (OSError, subprocess.SubprocessError, ValueError) as error:
            # Unknown presence never marks devices offline; report it once.
            if not self.station_error_shown:
                print('Presence unavailable; devices will not be marked offline:', type(error).__name__, str(error)[:160])
                self.station_error_shown = True
            return None

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
        known = self.agent.inventory.get(mac)
        # Never let a guest claim the IP of another configured/discovered MAC.
        if any(d.ip == address and d.mac != mac for d in self.agent.inventory.devices.values()):
            return
        if known is None:
            if len(self.agent.inventory.devices) >= self.limit:
                return
            protected = self.protect or (self.cloud is not None and mac in self.cloud.remote_protected)
            known = Device(mac, address, clean_name(name) if name else 'Guest ' + mac[-8:],
                           protected=protected, simulated=self.agent.enforcer.simulated)
            known.risk_facts['_demo_discovered'] = True
            known.assessment = self.agent.detector.assess_device(known)
            self.agent.inventory.devices[mac] = known
            self.collector.windows[mac] = deque()
            if not self.agent.enforcer.simulated:
                self.agent.enforcer.allowed.add(mac)
            if self.protect and self.cloud is not None:
                self.cloud.local_protected.add(mac)
            self.discovered[mac] = {'mac': mac, 'ip': address, 'name': known.name}
            self.agent._event('new_device', mac, {'discovery_source': source,
                'identity_verified': False, 'name_inferred': bool(name),
                'protected': protected, 'note': 'Discovery does not establish compromise or device type'})
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
        if seen:
            known.last_seen = self.agent.clock()
            # A packet from the device proves it is back, even before the next station poll.
            self.absent_since.pop(mac, None)
            if not known.present:
                self._set_present(known, True, 'captured_source')

    def _set_present(self, device, present, source):
        device.present = present
        # The API keeps the newest snapshot, so presence changes need a newer
        # snapshot_at. last_seen stays the last packet time.
        now = self.agent.clock()
        device.snapshot_at = max(now, max(device.snapshot_at or 0, device.last_seen or 0) + 0.000001)
        self.agent._event('device_online' if present else 'device_offline', device.mac,
            {'presence_source': source, 'note': 'Wi-Fi association change; not evidence of compromise'})

    def _presence(self, stations):
        now = self.agent.clock()
        for device in self.agent.inventory.devices.values():
            try:
                if ipaddress.ip_address(device.ip) not in self.network:
                    continue  # e.g. the management Mac on the cable: not a Wi-Fi client
            except ValueError:
                continue
            if device.mac in stations:
                self.absent_since.pop(device.mac, None)
                if not device.present:
                    self._set_present(device, True, 'associated')
            else:
                since = self.absent_since.setdefault(device.mac, now)
                if device.present and now - since >= self.OFFLINE_AFTER:
                    self._set_present(device, False, 'not_associated')

    def observe(self, record):
        # Source only: never register an internet destination as a LAN device.
        self.register(record.source_mac, record.source_ip, None, 'captured_source', seen=True)

    def tick(self):
        try:
            rows, stations = self.snapshots.get_nowait()
        except queue.Empty:
            rows, stations = [], None
        for mac, address, name, source in rows:
            self.register(mac, address, name, source)
        if stations is not None:
            self._presence(stations)
        if self.dirty and time.monotonic() - self.last_save >= 2:
            from .cloud_loop import atomic_json
            atomic_json(self.path, {'version': 1, 'devices': list(self.discovered.values())})
            self.dirty = False
            self.last_save = time.monotonic()
        # last_seen changes on every packet; a 30-second save keeps SD card writes low.
        if time.monotonic() - self.presence_saved >= 30:
            self._save_presence()

    def close(self):
        self.stop.set()
        if self.worker:
            self.worker.join(timeout=2)
        self.last_save = 0
        self.presence_saved = 0
        self.tick()
