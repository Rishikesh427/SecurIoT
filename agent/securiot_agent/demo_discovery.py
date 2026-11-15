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
            if len(inventory.devices) >= min(20, int(config.get('max_devices', 20))):
                break
            inventory.devices[mac] = Device(mac, str(address), clean_name(row.get('name') or 'Guest ' + mac[-8:]),
                protected=config.get('protect_guests', False), simulated=simulated,
                risk_facts={'_demo_discovered': True})


class DemoDiscovery:
    # A station must stay unassociated this long before it is shown offline, so a
    # quick Wi-Fi reconnect or roam does not flicker the dashboard. A device that
    # announces it is leaving (the AP reports "del station") only needs a short
    # grace; one that silently disappears from the station list waits longer.
    OFFLINE_AFTER = 15
    LEAVE_GRACE = 3
    STATION_EVENT = re.compile(r'(\S+): (new|del) station ([0-9a-fA-F:]{17})')

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
        self.protect = config.get('protect_guests', False)
        if type(self.protect) is not bool:
            raise ValueError('protect_guests must be boolean')
        self.excluded = {normalize_mac(m) for m in config.get('excluded_macs', [])}
        try:
            self.excluded.add(normalize_mac(Path('/sys/class/net', iface, 'address').read_text().strip()))
        except OSError:
            pass
        self.leases = Path(config['leases']) if config.get('leases') else None
        self.limit = min(20, int(config.get('max_devices', 20)))
        if not len(agent.inventory.devices) <= self.limit <= 20:
            raise ValueError('Configured inventory exceeds supported capacity')
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
        self.absent_since = {}
        self.station_error_shown = False
        self.stations = None          # last known associated set; None = unknown
        self.left = set()             # stations the AP reported leaving
        self.station_events = queue.Queue()
        self.event_at = {}            # mac -> (associated?, monotonic time) from the newest event
        self.watcher = None
        self.watch_process = None
        self.changed = False
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
                if self.agent.enforcer.simulated:
                    self.register(row['mac'], row['ip'], row.get('name'), 'saved_discovery', seen=False)
        for device in list(self.agent.inventory.devices.values()):
            if device.risk_facts.get('_demo_discovered'):
                self._identify(device)
        # Uploads require last_seen, so a device that left before a restart could
        # never be reported offline unless its last packet time survives restarts.
        self.presence_path = agent.storage.directory / 'presence.json'
        self.presence_saved = 0
        self._restore_last_seen()

    def _restore_last_seen(self):
        saved, offline = {}, set()
        if self.presence_path.exists():
            try:
                data = json.loads(self.presence_path.read_text())
                saved = data.get('last_seen', {}) if isinstance(data.get('last_seen'), dict) else {}
                offline = {m for m in data.get('offline', []) if isinstance(m, str)}
            except (OSError, ValueError):
                saved, offline = {}, set()
        legacy = self.path.stat().st_mtime if self.path.exists() else None
        for device in self.agent.inventory.devices.values():
            # A device that was gone at shutdown starts gone, so a restart does not
            # briefly put it back on the dashboard; association brings it back.
            if device.mac in offline:
                device.present = False
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
        devices = self.agent.inventory.devices.values()
        atomic_json(self.presence_path, {'version': 1,
            'last_seen': {d.mac: d.last_seen for d in devices if d.last_seen is not None},
            'offline': sorted(d.mac for d in devices if not d.present)})
        self.presence_saved = time.monotonic()

    def start(self):
        self.worker = threading.Thread(target=self._poll, daemon=True, name='demo-discovery')
        self.worker.start()
        self.watcher = threading.Thread(target=self._watch, daemon=True, name='station-events')
        self.watcher.start()

    def _watch(self):
        """Stream AP join/leave events so presence does not wait for the next poll."""
        try:
            self.watch_process = subprocess.Popen(['iw', 'event'], stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, text=True)
        except OSError as error:
            print('Station events unavailable; using the 2-second station poll:', type(error).__name__)
            return
        for line in self.watch_process.stdout:
            if self.stop.is_set():
                break
            match = self.STATION_EVENT.search(line)
            if match and match.group(1) == self.iface:
                try:
                    self.station_events.put((match.group(2) == 'new', normalize_mac(match.group(3)), time.monotonic()))
                except ValueError:
                    pass

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
            taken_at = time.monotonic()  # before reading, so a newer event always wins
            stations = self._stations()
            try:
                self.snapshots.put_nowait((rows, stations, taken_at))
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
        if name and source == 'dhcp_lease':
            self.fingerprints.update(mac, hostname=name)   # lease hostname is the best phone/Arduino hint
        known = self.agent.inventory.get(mac)
        # Never let a guest claim the IP of another configured/discovered MAC.
        if any(d.ip == address and d.mac != mac for d in self.agent.inventory.devices.values()):
            return
        if known is None:
            if len(self.agent.inventory.devices) >= self.limit:
                return
            hard_protected = mac in getattr(self.agent.enforcer, 'protected', set())
            protected = self.protect or hard_protected or (self.cloud is not None and mac in self.cloud.remote_protected)
            facts = self.fingerprints.facts(mac)
            label = facts['inferred'].get('label')
            known = Device(mac, address, clean_name(name) if name else clean_name('Guest ' + (label + ' ' if label else '') + mac[-8:]),
                           protected=protected, simulated=self.agent.enforcer.simulated)
            known.risk_facts['_demo_discovered'] = True
            known.risk_facts['_manual_protected'] = hard_protected
            if hard_protected:
                self.agent.manual_protected.add(mac)
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
        self.presence_saved = 0  # save on the next tick so a restart sees the change
        self.changed = True      # tells the live loop to upload now, not on the next cycle

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
                self.left.discard(device.mac)
                if device.last_seen is None:
                    # Associated but quiet (an idle phone): being on the Wi-Fi is enough
                    # to list it. Uploads require last_seen, so without this it stayed hidden.
                    device.last_seen = now
                    self.changed = True
                if not device.present:
                    self._set_present(device, True, 'associated')
            else:
                since = self.absent_since.setdefault(device.mac, now)
                grace = self.LEAVE_GRACE if device.mac in self.left else self.OFFLINE_AFTER
                if device.present and now - since >= grace:
                    self._set_present(device, False, 'left_network' if device.mac in self.left else 'not_associated')

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
        """Apply discovery and presence updates; True when presence changed (upload now)."""
        try:
            rows, stations, taken_at = self.snapshots.get_nowait()
        except queue.Empty:
            rows, stations, taken_at = [], None, 0
        for mac, address, name, source in rows:
            self.register(mac, address, name, source)
        if stations is not None:
            # An AP event newer than this poll is more current than the poll.
            for mac, (associated, at) in self.event_at.items():
                if at > taken_at:
                    (stations.add if associated else stations.discard)(mac)
            self.stations = stations
        while True:
            try:
                associated, mac, at = self.station_events.get_nowait()
            except queue.Empty:
                break
            self.event_at[mac] = (associated, at)
            if associated:
                self.left.discard(mac)
            else:
                self.left.add(mac)
                self.absent_since[mac] = self.agent.clock()
            if self.stations is not None:
                (self.stations.add if associated else self.stations.discard)(mac)
        if self.stations is not None:
            self._presence(self.stations)
        if self.dirty and time.monotonic() - self.last_save >= 2:
            from .cloud_loop import atomic_json
            atomic_json(self.path, {'version': 1, 'devices': list(self.discovered.values())})
            self.dirty = False
            self.last_save = time.monotonic()
        # last_seen changes on every packet; a 30-second save keeps SD card writes low.
        if time.monotonic() - self.presence_saved >= 30:
            self._save_presence()
        changed, self.changed = self.changed, False
        return changed

    def close(self):
        self.stop.set()
        if self.watch_process is not None:
            self.watch_process.terminate()
        if self.worker:
            self.worker.join(timeout=2)
        self.last_save = 0
        self.presence_saved = 0
        self.tick()
