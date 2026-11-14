"""Live capture into the same collector -> detector -> safety-policy path as replay.

Enforcement stays mocked. Needs root (raw capture) and `agent[replay]` (Scapy).
"""
import dataclasses
import time
from pathlib import Path

from .collector import TrafficCollector
from .enforcement import MockEnforcer
from .ml_adapter import MLAdapter
from .packets import decode_packet
from .replay import load_devices
from .runtime import Agent
from .storage import Storage


def build(devices: Path, state_dir: Path, *, armed=False, decoy_ips=(), clock=time.time):
    inventory = load_devices(devices)
    detector = MLAdapter(clock, (d.mac for d in inventory.devices.values() if d.protected))
    agent = Agent(inventory, detector, MockEnforcer(), Storage(state_dir), clock=clock)
    for device in inventory.devices.values():
        device.assessment = detector.assess_device(device)
    if armed:
        agent.set_armed(True)
    return agent, TrafficCollector(inventory.devices, decoy_ips=decoy_ips)


def make_handler(agent, collector, on_event=print):
    last = [0.0]

    def handle(packet):
        record = decode_packet(packet)
        if record is None:
            return
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


def run_live(iface, devices, state_dir, armed=False, decoy_ips=()):
    from scapy.all import sniff
    agent, collector = build(devices, state_dir, armed=armed, decoy_ips=decoy_ips)
    print(f"SECURIOT LIVE on {iface}: {'ARMED (mock actions)' if armed else 'learning mode'}; "
          f"{len(collector.windows)} known devices; 30 s warmup. Ctrl+C to stop.")
    try:
        sniff(iface=iface, prn=make_handler(agent, collector, show), store=False)
    except KeyboardInterrupt:
        print("Stopped.")
