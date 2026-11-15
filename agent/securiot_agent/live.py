"""Live capture into the same collector -> detector -> safety-policy path as replay.

Default enforcement is mocked. Linux enforcement requires explicit configuration.
"""
import dataclasses
import time
import queue
import threading
from pathlib import Path

from .collector import TrafficCollector
from .enforcement import MockEnforcer
from .ml_adapter import MLAdapter
from .packets import decode_packet
from .replay import load_devices
from .runtime import Agent
from .storage import Storage


def build(devices: Path, state_dir: Path, *, armed=False, decoy_ips=(), clock=time.time, model_mode="rules", linux_config=None):
    from .inventory import Inventory
    inventory = Inventory([]) if devices is None else load_devices(devices, simulated=linux_config is None)
    from .demo_discovery import prepare_inventory
    if devices is not None:
        prepare_inventory(inventory, state_dir, linux_config is None)
    detector = MLAdapter(clock, (d.mac for d in inventory.devices.values() if d.protected), model_mode=model_mode)
    enforcer = MockEnforcer()
    if linux_config is not None:
        from .linux_enforcement import LinuxEnforcer
        enforcer = LinuxEnforcer(linux_config, state_dir, [dataclasses.replace(d, protected=False) if d.risk_facts.get('_demo_discovered') else d for d in inventory.devices.values()])
        if devices is None:
            # Retain durable real restrictions when discovery starts empty. Only
            # journaled devices need cached identity for Restore after restart.
            restricted = set(enforcer.state['desired']) | set(enforcer.state['confirmed'])
            enforcer.allowed.update(restricted)
            if restricted:
                prepare_inventory(inventory, state_dir, False)
                inventory.devices = {mac: device for mac, device in inventory.devices.items() if mac in restricted}
        for device in inventory.devices.values():
            device.protected = device.mac in enforcer.protected if devices is None else device.protected or device.mac in enforcer.protected
    try:
        agent = Agent(inventory, detector, enforcer, Storage(state_dir, "linux" if linux_config else "simulation"), clock=clock)
    except BaseException:
        if not enforcer.simulated:
            enforcer.close()
        raise
    for device in inventory.devices.values():
        device.assessment = detector.assess_device(device)
    if armed:
        agent.set_armed(True)
    return agent, TrafficCollector(inventory.devices, decoy_ips=decoy_ips)


def make_handler(agent, collector, on_event=print, discovery=None):
    last = [0.0]

    def handle(packet):
        record = decode_packet(packet)
        if record is None:
            return
        if discovery is not None:
            discovery.observe(record)
        ts = max(record.timestamp, last[0])      # collector requires non-decreasing time
        last[0] = ts
        if ts != record.timestamp:
            record = dataclasses.replace(record, timestamp=ts)
        for observation in collector.consume(record):
            event = agent.observe(observation)
            if event is not None:
                on_event(event)
    return handle


def show(event):
    d = event.evidence.get("detection", {})
    print(f"{time.strftime('%H:%M:%S')} {event.mac} {event.evidence.get('finding', event.kind)} "
          f"arp={d.get('arp_requests', '-')} targets={d.get('unique_syn_targets', '-')} "
          f"score={d.get('ml_score', d.get('anomaly', '-'))} -> {event.evidence.get('decision')} "
          f"{event.actions_taken or event.would_have}")


class LivePump:
    """Capture thread only enqueues; runtime, storage, and cloud have one writer."""
    def __init__(self, agent, collector, cloud=None, *, capacity=4096, on_event=show, discovery=None):
        self.agent = agent
        self.packets = queue.Queue(maxsize=capacity)
        self.discovery = discovery
        self.handle = make_handler(agent, collector, on_event, discovery)
        self.cloud = cloud
        self.dropped = 0
        self._routine_dropped = 0
        self.next_poll = 0.0
        self.cloud_failures = 0
        self.next_upkeep = 0.0

    def receive(self, packet):
        try:
            self.packets.put_nowait(packet)
        except queue.Full:
            self.dropped += 1

    def step(self, now, *, wait=0.1):
        if self.agent.routine is not None and self.dropped != self._routine_dropped:
            for mac in self.agent.routine.windows:
                self.agent.routine.flag(mac)
            self._routine_dropped = self.dropped
        self.agent.routine_tick()
        try:
            self.handle(self.packets.get(timeout=wait))
        except queue.Empty:
            pass
        if self.discovery is not None and self.discovery.tick():
            self.next_poll = now  # a device joined or left: upload it right away
        upkeep = getattr(self.agent.enforcer, "maintain", None)
        if upkeep is not None and now >= self.next_upkeep:
            # nl80211 APs have no deny list: re-kick quarantined stations that rejoin.
            self.next_upkeep = now + 1
            from .linux_enforcement import EnforcementError
            try:
                for mac in upkeep():
                    print(f"Quarantine: removed {mac} again after it rejoined the Wi-Fi")
            except (EnforcementError, ValueError) as error:
                print("Quarantine upkeep failed; firewall drop still applies:", error)
        if self.cloud is not None and now >= self.next_poll:
            errors = self.cloud.tick()
            for error in errors:
                print(f"Cloud: {error}; pending work retained")
            self.cloud_failures = min(5, self.cloud_failures + 1) if errors else 0
            self.next_poll = now + (min(30, 2 ** self.cloud_failures) if errors else .5)


def run_live(iface, devices, state_dir, armed=False, decoy_ips=(), model_mode="required", *,
             linux_config=None, api_url=None, api_key=None):
    import os
    if linux_config is None:
        raise ValueError('Live operation requires real Linux enforcement configuration')
    if not os.environ.get('SECURIOT_DISCOVERY_CONFIG'):
        raise ValueError('Live operation requires discovery configuration')
    from scapy.all import AsyncSniffer
    if linux_config is not None and linux_config.ap_interface != iface:
        raise ValueError("Capture must use the configured AP interface")
    agent, collector = build(devices, state_dir, armed=armed, decoy_ips=decoy_ips,
                             model_mode=model_mode, linux_config=linux_config)
    sniffer = None
    discovery = None
    try:
        cloud = None
        if api_url:
            from .cloud import CloudClient
            from .cloud_loop import CloudLoop
            cloud = CloudLoop(agent, CloudClient(api_url, api_key),
                              Path(__file__).resolve().parents[2] / "contract/schemas.json", permit_arm=armed)
            for error in cloud.tick(upload=False):
                print(f"Cloud: {error}; local processing continues")
        import os, json
        config_path = os.environ.get('SECURIOT_DISCOVERY_CONFIG')
        if config_path:
            from .demo_discovery import DemoDiscovery
            discovery = DemoDiscovery(json.loads(Path(config_path).read_text()), agent, collector, cloud, iface)
            discovery.start()
        pump = LivePump(agent, collector, cloud, discovery=discovery)
        mode = "mock actions" if agent.enforcer.simulated else "REAL Linux enforcement"
        print(f"SECURIOT LIVE on {iface}: {'ARMED' if armed else 'learning mode'} ({mode}); "
              f"{len(collector.windows)} known devices; 30 s automatic warmup. Ctrl+C to stop.")
        print("Model:", agent.detector.model_status)
        ready = threading.Event()
        sniffer = AsyncSniffer(iface=iface, prn=pump.receive, store=False, started_callback=ready.set)
        sniffer.start()
        if not ready.wait(5):
            if not sniffer.running:
                sniffer.join()
            raise OSError("Live capture did not become ready")
        while True:
            pump.step(time.monotonic())
            # Surface asynchronous capture errors instead of polling commands forever.
            if not sniffer.running:
                sniffer.join()
                raise OSError("Live capture stopped unexpectedly")
    except KeyboardInterrupt:
        print("Stopped; existing restrictions and pending cloud work are retained.")
    finally:
        if agent.routine is not None:
            agent.routine.save(agent.clock(), force=True)
        if sniffer is not None and sniffer.running:
            sniffer.stop()
        if discovery is not None:
            discovery.close()
        if 'pump' in locals() and pump.dropped:
            print(f"Capture overloaded: {pump.dropped} packets dropped; detection coverage was incomplete.")
        if not agent.enforcer.simulated:
            agent.enforcer.close()
