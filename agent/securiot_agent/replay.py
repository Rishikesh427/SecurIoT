"""Connect saved packet files to the existing agent, with mock enforcement only."""

from dataclasses import dataclass
import ipaddress
import json
from pathlib import Path
import time

from .collector import TrafficCollector
from .detection import ReplayPreviewDetector
from .enforcement import MockEnforcer
from .inventory import Inventory
from .models import Device, Event
from .packets import CaptureStats, read_capture
from .runtime import Agent
from .simulation import DemoClock
from .storage import Storage


def load_devices(path: Path) -> Inventory:
    """Read local known-device configuration, not risk scores/persona claims."""
    try:
        data = json.loads(path.read_text())
        records = data["devices"] if isinstance(data, dict) else data
        if not isinstance(records, list) or not records:
            raise ValueError("Expected a nonempty devices list")
        devices = []
        for record in records:
            if not isinstance(record, dict):
                raise ValueError("Each device must be an object")
            if type(record.get("protected", False)) is not bool:
                raise ValueError("protected must be true or false")
            name = record.get("label") or record["name"]
            if not isinstance(name, str) or not name.strip():
                raise ValueError("Device name must be a nonempty string")
            ipaddress.ip_address(record["ip"])
            for key in ("eol", "default_creds", "cloud_only"):
                if record.get(key) is not None and type(record[key]) is not bool:
                    raise ValueError(f"{key} must be boolean or null")
            for key in ("vendor", "model"):
                if record.get(key) is not None and not isinstance(record[key], str):
                    raise ValueError(f"{key} must be a string or null")
            ports = record.get("ports", [])
            if not isinstance(ports, list) or any(type(port) is not int or not 1 <= port <= 65535 for port in ports):
                raise ValueError("ports must be a list of integers from 1 to 65535")
            admin_ports = record.get("admin_ports", [])
            if not isinstance(admin_ports, list) or any(type(port) is not int or port not in ports for port in admin_ports):
                raise ValueError("admin_ports must be a subset of reported integer ports")
            devices.append(Device(record["mac"], record["ip"], name,
                                  protected=record.get("protected", False), simulated=record.get("simulated", True) is True,
                                  risk_facts={key: record[key] for key in (
                                      "ports", "admin_ports", "vendor", "model", "eol", "default_creds", "cloud_only"
                                  ) if key in record}))
            devices[-1].risk_facts["_simulated_facts"] = record.get("simulated") is True
            if "persona" in record:
                if record.get("simulated") is not True or not isinstance(record["persona"], dict):
                    raise ValueError("A persona requires an explicitly simulated device")
                allowed = {"vendor", "model", "type", "eol", "cloud_only", "kev"}
                if set(record["persona"]) - allowed:
                    raise ValueError("Persona contains unsupported fields")
                for key in ("eol", "cloud_only"):
                    if key in record["persona"] and type(record["persona"][key]) is not bool:
                        raise ValueError(f"Persona {key} must be boolean")
                for key in ("vendor", "model", "type"):
                    if key in record["persona"] and not isinstance(record["persona"][key], str):
                        raise ValueError(f"Persona {key} must be a string")
                if "kev" in record["persona"] and record["persona"]["kev"] not in {"confirmed", "possible", "none", "unknown"}:
                    raise ValueError("Invalid persona KEV confidence")
                devices[-1].risk_facts["persona"] = record["persona"]
        return Inventory(devices)
    except (ValueError, KeyError, TypeError) as error:
        raise ValueError(f"Invalid devices file {path}: {error}") from error


@dataclass
class ReplayResult:
    agent: Agent
    capture: CaptureStats
    collector: TrafficCollector
    events: list[Event]
    capture_duration: float


def replay_capture(path: Path, inventory: Inventory, storage: Storage, *, armed: bool = False, detector: str = "preview", ready=None, progress=None, detector_factory=None, decoy_ips=(), model_mode="rules") -> ReplayResult:
    # Preserve packet spacing, but map an old capture onto this replay's clock.
    # This avoids moving persisted cooldown/grace timers backwards on reuse.
    saved = storage.load_state()
    clock = DemoClock(max(time.time(), saved["saved_at"]) + 1)
    started_at = clock()
    if detector_factory is not None:
        implementation = detector_factory(clock=clock, protected_macs=[d.mac for d in inventory.devices.values() if d.protected])
    elif detector == "ml":
        from .ml_adapter import MLAdapter
        implementation = MLAdapter(clock, (d.mac for d in inventory.devices.values() if d.protected), model_mode=model_mode)
    elif detector == "preview":
        implementation = ReplayPreviewDetector()
    else:
        raise ValueError(f"Unknown detector: {detector}")
    if not callable(getattr(implementation, "observe", None)) or (detector_factory is not None and not callable(getattr(implementation, "assess_device", None))):
        raise ValueError("Detector adapter must implement observe() and assess_device()")
    agent = Agent(inventory, implementation, MockEnforcer(), storage, clock=clock)
    if detector == "ml":
        for device in inventory.devices.values():
            device.assessment = implementation.assess_device(device)
    if armed:
        agent.set_armed(True)
    if ready is not None:
        ready(agent)
    collector = TrafficCollector(inventory.devices, decoy_ips=decoy_ips)
    capture = CaptureStats()
    events = []
    first_timestamp = last_timestamp = None
    for packet in read_capture(path, capture):
        if first_timestamp is None:
            first_timestamp = packet.timestamp
        last_timestamp = packet.timestamp
        clock.now = started_at + packet.timestamp - first_timestamp
        for observation in collector.consume(packet):
            event = agent.observe(observation)
            if event is not None:
                events.append(event)
        if progress is not None:
            progress(agent)
    duration = last_timestamp - first_timestamp if first_timestamp is not None else 0
    return ReplayResult(agent, capture, collector, events, duration)


def run_replay(path: Path, devices_path: Path, state_dir: Path, armed: bool, detector: str = "ml", decoy_ips=(), model_mode="required") -> None:
    print("SECURIOT — OFFLINE PACKET REPLAY / MOCK ENFORCEMENT")
    print("Reads a file only. Capture timing is preserved; no live packets or firewall commands are sent.")
    print("The 30-second startup warmup uses capture time. --arm enables mock actions only.")
    result = replay_capture(path, load_devices(devices_path), Storage(state_dir), armed=armed, detector=detector, decoy_ips=decoy_ips, model_mode=model_mode)
    print("Model:", getattr(result.agent.detector, "model_status", {"active": False, "mode": "preview"}))
    print(f"\nCapture: {path}")
    print(f"Frames: {result.capture.frames_read}; Ethernet: {result.capture.ethernet_frames}; "
          f"unsupported/skipped: {result.capture.skipped_frames}")
    print(f"Matched to known devices: {result.collector.matched_frames}; "
          f"unmatched: {result.collector.unmatched_frames}; duration: {result.capture_duration:.3f}s")
    print(f"\nScan findings: {len(result.events)} (detector: {detector})")
    for event in result.events:
        detection = event.evidence["detection"]
        print(f"  {event.mac}: {event.evidence['finding']}, "
              f"{detection['unique_syn_targets']} SYN targets, {detection['arp_requests']} ARP requests")
        print(f"    Decision: {event.evidence['decision']}; "
              f"actions: {', '.join(event.actions_taken) or 'none'}; "
              f"would have: {', '.join(event.would_have) or 'none'}")
    print("\nInventory (captured frame bytes, counted once per direction):")
    for device in result.agent.inventory.devices.values():
        print(f"  {device.name}: {device.status}; in={device.bytes_in}, out={device.bytes_out}; "
              f"destinations={len(device.dests)}; DNS={', '.join(repr(n) for n in device.dns_queries) or 'none'}")
        if device.assessment:
            score = device.assessment
            print(f"    C assessment: risk={score['risk']}, band={score['band']}, confidence={score['confidence']}")
            for reason in score['reasons']:
                print(f"      {reason}")
    if result.capture.frames_read and not result.collector.matched_frames:
        print("\nNo configured device MACs matched. Supply your known MACs using --devices.")
    print(f"\nAudit/outbox: {result.agent.storage.outbox_path.resolve()}")
    print("No cloud upload is performed. Any saved restrictions belong to the mock backend.")
