"""Behavior tests for the simulated local loop; no real networking involved."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

AGENT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(AGENT_DIR))

from securiot_agent.detection import DemoDetector
from securiot_agent.enforcement import MockEnforcer
from securiot_agent.inventory import Inventory
from securiot_agent.models import Device, Observation
from securiot_agent.policy import Policy
from securiot_agent.runtime import Agent
from securiot_agent.simulation import CAMERA_MAC, LAPTOP_MAC, DemoClock, scan
from securiot_agent.storage import Storage


class AgentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.storage = Storage(Path(self.temp.name))
        self.clock = DemoClock(1_000)
        self.enforcer = MockEnforcer()
        self.agent = self.make_agent()

    def make_agent(self, *, enforcer=None, camera_protected=False):
        return Agent(
            Inventory([
                Device(CAMERA_MAC, "10.42.0.20", "Camera", protected=camera_protected),
                Device(LAPTOP_MAC, "10.42.0.2", "Laptop", protected=True),
            ]),
            DemoDetector(), enforcer if enforcer is not None else self.enforcer,
            self.storage, clock=self.clock,
        )

    def arm_after_warmup(self):
        self.agent.set_armed(True)
        self.clock.advance(30)

    def test_learning_mode_records_proposal_without_restricting(self):
        self.clock.advance(30)
        event = self.agent.observe(scan())
        self.assertEqual(event.would_have, ["quarantine"])
        self.assertEqual(event.actions_taken, [])
        self.assertEqual(self.enforcer.calls, [])
        self.assertEqual(self.agent.inventory.get(CAMERA_MAC).status, "normal")
        saved_event = self.storage.pending_events()[0]
        self.assertEqual(saved_event["id"], event.id)
        self.assertTrue(saved_event["simulated"])

    def test_armed_detection_quarantines_and_audits_success(self):
        self.arm_after_warmup()
        event = self.agent.observe(scan())
        self.assertEqual(event.actions_taken, ["quarantine"])
        self.assertEqual(self.enforcer.restrictions[CAMERA_MAC], "quarantined")
        self.assertEqual(self.agent.inventory.get(CAMERA_MAC).status, "quarantined")
        self.assertEqual(self.storage.load_state()["devices"][CAMERA_MAC]["status"], "quarantined")
        self.assertEqual(self.storage.pending_events()[-1]["actions_taken"], ["quarantine"])

    def test_warmup_blocks_an_armed_action_until_exact_boundary(self):
        self.agent.set_armed(True)
        self.clock.advance(29)
        self.assertEqual(self.agent.observe(scan()).evidence["decision"], "startup_warmup")
        self.assertEqual(self.enforcer.calls, [])
        self.clock.advance(1)
        self.assertEqual(self.agent.observe(scan()).actions_taken, ["quarantine"])

    def test_protected_device_cannot_be_restricted_by_detection_or_manual_action(self):
        self.arm_after_warmup()
        event = self.agent.observe(scan(LAPTOP_MAC))
        manual = self.agent.request_action("block_wan", LAPTOP_MAC)
        self.assertEqual(event.evidence["decision"], "protected_device")
        self.assertEqual(manual.evidence["decision"], "protected_device")
        self.assertEqual(self.enforcer.calls, [])

    def test_unknown_device_is_not_promoted_to_known_by_observation(self):
        self.arm_after_warmup()
        unknown = "02:00:00:00:00:99"
        event = self.agent.observe(scan(unknown))
        self.assertEqual(event.kind, "observation_ignored")
        self.assertEqual(self.agent.request_action("quarantine", unknown).evidence["decision"],
                         "rejected_unknown_device")
        self.assertIsNone(self.agent.inventory.get(unknown))
        self.assertEqual(self.enforcer.calls, [])

    def test_restore_is_immediate_and_grace_expires_at_exact_boundary(self):
        self.arm_after_warmup()
        self.agent.observe(scan())
        self.agent.set_armed(False)
        restored = self.agent.request_action("restore", CAMERA_MAC)
        self.assertEqual(restored.actions_taken, ["restore"])
        self.assertEqual(self.enforcer.restrictions, {})
        self.agent.set_armed(True)
        self.clock.advance(59)
        self.assertEqual(self.agent.observe(scan()).evidence["decision"], "restore_grace")
        self.clock.advance(1)
        self.assertEqual(self.agent.observe(scan()).actions_taken, ["quarantine"])

    def test_action_cooldown_prevents_immediate_escalation(self):
        self.arm_after_warmup()
        self.agent.request_action("block_wan", CAMERA_MAC)
        self.clock.advance(9)
        self.assertEqual(self.agent.observe(scan()).evidence["decision"], "action_cooldown")
        self.assertEqual(self.enforcer.restrictions[CAMERA_MAC], "blocked")
        self.clock.advance(1)
        self.assertEqual(self.agent.observe(scan()).actions_taken, ["quarantine"])
        self.clock.advance(10)
        self.assertEqual(self.agent.request_action("block_wan", CAMERA_MAC).evidence["decision"],
                         "already_restricted")
        self.assertEqual(self.enforcer.restrictions[CAMERA_MAC], "quarantined")

    def test_restore_all_clears_both_kinds_of_restriction_in_learning_mode(self):
        self.agent.inventory.devices["02:00:00:00:00:30"] = Device(
            "02:00:00:00:00:30", "10.42.0.30", "Projector")
        self.arm_after_warmup()
        self.agent.request_action("block_wan", CAMERA_MAC)
        self.agent.request_action("quarantine", "02:00:00:00:00:30")
        self.agent.set_armed(False)
        event = self.agent.request_action("restore_all")
        self.assertEqual(len(event.evidence["restored_macs"]), 2)
        self.assertEqual(event.actions_taken, ["restore_all"])
        self.assertEqual(self.enforcer.restrictions, {})
        self.assertTrue(all(d.status == "normal" for d in self.agent.inventory.devices.values()))

    def test_restart_reapplies_restrictions_but_returns_to_learning_mode(self):
        self.arm_after_warmup()
        event = self.agent.observe(scan())
        restarted_backend = MockEnforcer()
        restarted = self.make_agent(enforcer=restarted_backend)
        self.assertTrue(restarted.policy.learning_mode)
        self.assertEqual(restarted.inventory.get(CAMERA_MAC).status, "quarantined")
        self.assertEqual(restarted_backend.restrictions[CAMERA_MAC], "quarantined")
        self.assertEqual(self.storage.pending_events()[-1]["kind"], "state_reapplied")
        self.assertIn(event.id, [e["id"] for e in self.storage.pending_events()])
        # A user can undo saved restrictions even during the new startup warmup.
        self.assertEqual(restarted.request_action("restore", CAMERA_MAC).actions_taken, ["restore"])

    def test_restart_preserves_restore_grace(self):
        self.arm_after_warmup()
        self.agent.observe(scan())
        self.agent.request_action("restore", CAMERA_MAC)
        restarted = self.make_agent(enforcer=MockEnforcer())
        restarted.set_armed(True)
        self.clock.advance(30)
        self.assertEqual(restarted.observe(scan()).evidence["decision"], "restore_grace")
        self.clock.advance(30)
        self.assertEqual(restarted.observe(scan()).actions_taken, ["quarantine"])

    def test_now_protected_device_is_not_restricted_from_saved_state(self):
        self.arm_after_warmup()
        self.agent.observe(scan())
        restarted_backend = MockEnforcer()
        restarted = self.make_agent(enforcer=restarted_backend, camera_protected=True)
        self.assertEqual(restarted.inventory.get(CAMERA_MAC).status, "normal")
        self.assertEqual(restarted_backend.calls, [])
        self.assertEqual(self.storage.pending_events()[-1]["kind"], "state_skipped")

    def test_failed_enforcement_never_claims_success(self):
        class FailingEnforcer(MockEnforcer):
            def apply(self, action, mac):
                raise OSError("Simulated backend failure")

        agent = self.make_agent(enforcer=FailingEnforcer())
        agent.set_armed(True)
        self.clock.advance(30)
        event = agent.observe(scan())
        self.assertEqual(event.actions_taken, [])
        self.assertEqual(event.evidence["decision"], "enforcement_failed: OSError")
        self.assertEqual(agent.inventory.get(CAMERA_MAC).status, "normal")

    def test_invalid_mac_unknown_action_and_unavailable_power_cycle_are_rejected(self):
        self.arm_after_warmup()
        for action, mac, expected in [
            ("quarantine", "bad-address", "rejected_invalid_mac"),
            ("run_shell", CAMERA_MAC, "rejected_unknown_action"),
            ("power_cycle", CAMERA_MAC, "rejected_unavailable_in_this_build"),
        ]:
            with self.subTest(action=action):
                self.assertEqual(self.agent.request_action(action, mac).evidence["decision"], expected)
        self.assertEqual(self.enforcer.calls, [])

    def test_corrupt_state_stops_startup(self):
        self.storage.state_path.write_text("{broken json")
        with self.assertRaisesRegex(ValueError, "Invalid state"):
            self.make_agent()

    def test_state_with_invalid_timestamp_stops_startup(self):
        self.storage.state_path.write_text(json.dumps({
            "version": 1, "mode": "simulation", "saved_at": -1, "devices": {},
        }))
        with self.assertRaisesRegex(ValueError, "Invalid state"):
            self.make_agent()

    def test_inventory_tracks_traffic_and_detector_counts_unique_targets(self):
        self.clock.advance(30)
        duplicate_targets = Observation(
            CAMERA_MAC, bytes_in=200, bytes_out=100,
            destinations=("192.0.2.10",), syn_targets=(("10.42.0.50", 80),) * 30,
        )
        self.assertIsNone(self.agent.observe(duplicate_targets))
        device = self.agent.inventory.get(CAMERA_MAC)
        self.assertEqual((device.bytes_in, device.bytes_out), (200, 100))
        self.assertEqual(device.dests, ["10.42.0.50", "192.0.2.10"])
        self.assertEqual(device.last_seen, self.clock())
        self.assertIsNone(DemoDetector().observe(Observation(CAMERA_MAC, arp_requests=29)))
        self.assertIsNotNone(DemoDetector().observe(Observation(CAMERA_MAC, arp_requests=30)))

    def test_local_safety_minimums_cannot_be_lowered_at_construction(self):
        policy = Policy(warmup_seconds=0, cooldown_seconds=0, restore_grace_seconds=0)
        self.assertEqual((policy.warmup_seconds, policy.cooldown_seconds, policy.restore_grace_seconds),
                         (30, 10, 60))


class CommandLineTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, str(AGENT_DIR / "agent.py"), *args],
            capture_output=True, text=True, timeout=15,
        )

    def test_default_simulation_stays_in_learning_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_cli("--simulate", "--state-dir", directory)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("SIMULATION ONLY", result.stdout)
            self.assertIn("Would have: quarantine", result.stdout)
            events = Storage(Path(directory)).pending_events()
            self.assertFalse(any(e["actions_taken"] for e in events))

    def test_armed_walkthrough_and_repeated_run(self):
        with tempfile.TemporaryDirectory() as directory:
            for _ in range(2):
                result = self.run_cli("--simulate", "--arm", "--state-dir", directory)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("Actions taken: quarantine", result.stdout)
                self.assertIn("Decision: restore_grace", result.stdout)
                self.assertIn("Decision: protected_device", result.stdout)
                self.assertIn("Actions taken: restore_all", result.stdout)
            storage = Storage(Path(directory))
            self.assertTrue(all(d["status"] == "normal" for d in storage.load_state()["devices"].values()))
            ids = [e["id"] for e in storage.pending_events()]
            self.assertEqual(len(ids), len(set(ids)))

    def test_live_mode_cannot_be_started(self):
        result = self.run_cli("--arm")
        self.assertEqual(result.returncode, 2)
        self.assertIn("--simulate", result.stderr)


if __name__ == "__main__":
    unittest.main()
