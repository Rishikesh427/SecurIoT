"""Readable walkthrough using synthetic traffic and a manually advanced clock."""

from dataclasses import asdict
from pathlib import Path
import time

from .detection import DemoDetector
from .enforcement import MockEnforcer
from .inventory import Inventory
from .models import Device, Event, Observation
from .runtime import Agent
from .storage import Storage

CAMERA_MAC = "02:00:00:00:00:20"
LAPTOP_MAC = "02:00:00:00:00:02"


class DemoClock:
    def __init__(self, now: float):
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def scan(mac: str = CAMERA_MAC) -> Observation:
    return Observation(
        mac=mac, bytes_out=1_200,
        syn_targets=tuple((f"10.42.0.{host}", 80) for host in range(50, 70)),
    )


def run_demo(state_dir: Path, armed: bool) -> None:
    storage = Storage(state_dir)
    saved = storage.load_state()
    clock = DemoClock(max(time.time(), saved["saved_at"]))
    inventory = Inventory([
        Device(CAMERA_MAC, "10.42.0.20", "Living room camera (simulated)"),
        Device(LAPTOP_MAC, "10.42.0.2", "Dashboard laptop (simulated)", protected=True),
    ])
    agent = Agent(inventory, DemoDetector(), MockEnforcer(), storage, clock=clock)

    def show(event: Event | None) -> None:
        if event is None:
            print("  No suspicious activity detected.")
            return
        print(f"  Decision: {event.evidence.get('decision', event.kind)}")
        print(f"  Actions taken: {', '.join(event.actions_taken) or 'none'}")
        if event.would_have:
            print(f"  Would have: {', '.join(event.would_have)}")
        if event.mac in inventory.devices:
            print(f"  Device status: {inventory.devices[event.mac].status}")

    print("SECURIOT — SIMULATION ONLY")
    print("Traffic is synthetic; actions change mock state only. No packets or firewall commands are sent.")
    print("Time advances artificially so the safety checks can run without waiting.")
    print("The demo MACs are locally administered; real demo devices will need stable addresses.")
    if any(device.status != "normal" for device in inventory.devices.values()):
        print("\nSaved mock restrictions were reapplied. Resetting them for this walkthrough:")
        show(agent.request_action("restore_all"))

    # Also let any persisted restore grace expire between walkthroughs.
    clock.advance(max(agent.policy.warmup_seconds, agent.policy.restore_grace_seconds) + 1)
    print("\n1. Camera sends normal traffic after startup warmup.")
    show(agent.observe(Observation(CAMERA_MAC, bytes_in=2_000, bytes_out=500,
                                   destinations=("192.0.2.10",))))
    print("\n2. Camera attempts 20 distinct targets in a synthetic 10-second window.")
    show(agent.observe(scan()))
    print("  Learning mode observes and records the proposed response.")

    if armed:
        print("\n3. You supplied --arm: explicitly arming the MOCK enforcer.")
        agent.set_armed(True)
        clock.advance(11)
        show(agent.observe(scan()))
        print("\n4. Restore the camera.")
        show(agent.request_action("restore", CAMERA_MAC))
        print("\n5. Another scan arrives immediately after Restore.")
        show(agent.observe(scan()))
        print("\n6. The protected dashboard laptop triggers the same detector.")
        show(agent.observe(scan(LAPTOP_MAC)))
        print("\n7. After the 60-second grace period, a new scan can trigger containment again.")
        clock.advance(61)
        show(agent.observe(scan()))
        print("\n8. Restore all is the final undo.")
        show(agent.request_action("restore_all"))
    else:
        print("\nTo see quarantine and Restore in the mock backend, rerun with --simulate --arm.")

    print("\nFinal inventory:")
    for device in inventory.devices.values():
        row = asdict(device)
        print(f"  {row['name']}: {row['status']}, {row['bytes_out']} bytes sent")
    print(f"\nLocal audit/outbox: {storage.outbox_path.resolve()}")
    print(f"Pending events: {len(storage.pending_events())}; cloud upload is not implemented yet.")
