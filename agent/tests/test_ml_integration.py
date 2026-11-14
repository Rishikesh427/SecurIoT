"""Exercise packets -> real securiot_ml -> safety policy -> mock enforcement."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

AGENT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(AGENT_DIR))
HAS_DEPS = all(importlib.util.find_spec(name) is not None for name in ("scapy", "securiot_ml"))
if HAS_DEPS:
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import ARP, Ether
    from scapy.utils import PcapWriter
    from securiot_agent.models import Observation
    from securiot_agent.replay import load_devices, replay_capture
    from securiot_agent.storage import Storage

MAC = "02:00:00:00:00:20"


@unittest.skipUnless(HAS_DEPS, "Install agent[replay] and editable ml to run combined tests")
class MLIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def replay(self, filename, armed=False, inventory=None):
        inventory = inventory or load_devices(AGENT_DIR / "fixtures/devices.json")
        return replay_capture(AGENT_DIR / "fixtures" / filename, inventory,
                              Storage(self.directory / filename), armed=armed, detector="ml")

    def test_normal_and_slow_traffic_do_not_produce_findings(self):
        normal = self.replay("normal.pcap", armed=True)
        self.assertEqual(normal.events, [])
        self.assertEqual(normal.agent.enforcer.calls, [])
        self.assertEqual(normal.agent.inventory.get(MAC).assessment["risk"], 0)
        # The ML detector reports slow target scans, but only as advisory evidence.
        slow = self.replay("slow_targets.pcap", armed=True)
        self.assertEqual(slow.agent.enforcer.calls, [])
        self.assertTrue(all(e.evidence["decision"] == "supporting_evidence_only" for e in slow.events))

    def test_target_scan_is_real_c_evidence_but_does_not_quarantine(self):
        result = self.replay("scan.pcap", armed=True)
        event = result.events[-1]
        self.assertEqual(event.evidence["finding"], "scan_targets")
        self.assertEqual(event.evidence["detection"]["detector"], "securiot_ml")
        self.assertEqual(event.evidence["detection"]["distinct_targets"], 20)
        self.assertEqual(event.evidence["decision"], "supporting_evidence_only")
        self.assertEqual(event.actions_taken, [])
        self.assertEqual(result.agent.enforcer.calls, [])
        # C maps 0.3 anomaly to 12 risk points. The agent does not scale twice.
        self.assertEqual(result.agent.inventory.get(MAC).assessment["risk"], 12)

    def test_arp_scan_learning_and_armed_behavior(self):
        for armed in (False, True):
            result = self.replay("arp_scan.pcap", armed=armed)
            scans = [e for e in result.events if e.evidence["finding"] == "scan_arp"]
            self.assertTrue(scans)
            event = scans[0]          # the ML detector may fire before the 30th request
            self.assertGreaterEqual(event.evidence["detection"]["arp_in_window"], 8)
            self.assertEqual(event.actions_taken, ["quarantine"] if armed else [])
            self.assertEqual(event.would_have, [] if armed else ["quarantine"])

    def test_protected_mac_is_ignored_by_c_and_never_enforced(self):
        result = self.replay("protected_arp.pcap", armed=True)
        self.assertEqual(result.events[-1].evidence["decision"], "protected_device")
        self.assertEqual(result.agent.enforcer.calls, [])

    def test_c_score_combines_explicit_fixture_facts_and_packet_evidence(self):
        inventory = load_devices(AGENT_DIR / "fixtures/devices.json")
        inventory.get(MAC).risk_facts = {
            "ports": [23], "default_creds": True,
            "persona": {"type": "camera", "vendor": "Edimax", "model": "IC-7100",
                        "kev": "possible", "eol": True},
        }
        normal = self.replay("normal.pcap", inventory=inventory)
        self.assertEqual(normal.agent.inventory.get(MAC).assessment["risk"], 75)
        inventory = load_devices(AGENT_DIR / "fixtures/devices.json")
        inventory.get(MAC).risk_facts = normal.agent.inventory.get(MAC).risk_facts
        scan = self.replay("arp_scan.pcap", inventory=inventory)
        self.assertEqual(scan.agent.inventory.get(MAC).assessment["risk"], 100)
        self.assertEqual(scan.agent.inventory.get(MAC).assessment["confidence"], "possible")

    def test_restore_grace_still_guards_real_c_findings(self):
        agent = self.replay("arp_scan.pcap", armed=True).agent
        self.assertEqual(agent.request_action("restore", MAC).actions_taken, ["restore"])
        agent.clock.advance(1)
        event = agent.observe(Observation(MAC, packet_arp_requests=1, arp_targets=tuple(f"10.42.0.{i}" for i in range(50, 80))))
        self.assertEqual(event.evidence["decision"], "restore_grace")
        agent.clock.advance(60)
        event = agent.observe(Observation(MAC, packet_arp_requests=30, arp_targets=tuple(f"10.42.0.{i}" for i in range(50, 80))))
        self.assertEqual(event.actions_taken, ["quarantine"])

    def test_rolling_totals_are_not_fed_back_into_c(self):
        # 29 genuine requests must never be reported as 30 or more, despite
        # cumulative snapshots of 1, 2, ... 29 being produced by our collector.
        path = self.directory / "below.pcap"
        baseline = Ether(src=MAC, dst="02:00:00:00:00:01") / IP(dst="10.42.0.1") / TCP(flags="A")
        baseline.time = 1000
        with PcapWriter(str(path), sync=True) as writer:
            writer.write(baseline)
            for index in range(29):
                packet = Ether(src=MAC, dst="ff:ff:ff:ff:ff:ff") / ARP(
                    hwsrc=MAC, psrc="10.42.0.20", pdst=f"10.42.0.{50 + index}")
                packet.time = 1032 + index * 0.1
                writer.write(packet)
        result = replay_capture(path, load_devices(AGENT_DIR / "fixtures/devices.json"),
                                Storage(self.directory / "below-state"), armed=True, detector="ml")
        for event in result.events:
            self.assertLess(event.evidence["detection"]["arp_in_window"], 30)

    def test_combined_cli_selects_ml_by_default(self):
        result = subprocess.run([
            sys.executable, str(AGENT_DIR / "agent.py"), "--replay",
            str(AGENT_DIR / "fixtures/arp_scan.pcap"), "--arm",
            "--state-dir", str(self.directory / "cli"), "--model-mode", "rules",
        ], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("detector: ml", result.stdout)
        self.assertIn("actions: quarantine", result.stdout)
        self.assertIn("C assessment: risk=40", result.stdout)

    def test_invalid_scoring_facts_and_forged_persona_are_rejected(self):
        for extra in ({"default_creds": "false"}, {"ports": ["23"]},
                      {"persona": {"anomaly": 1}, "simulated": True},
                      {"persona": {"eol": True}, "simulated": False}):
            path = self.directory / "invalid.json"
            path.write_text(json.dumps({"devices": [{
                "mac": MAC, "ip": "10.42.0.20", "name": "Camera", **extra,
            }]}))
            with self.assertRaises(ValueError):
                load_devices(path)

    def test_c_warmup_cannot_be_bypassed_by_arming(self):
        path = self.directory / "early.pcap"
        with PcapWriter(str(path), sync=True) as writer:
            for index in range(30):
                packet = Ether(src=MAC, dst="ff:ff:ff:ff:ff:ff") / ARP(
                    hwsrc=MAC, psrc="10.42.0.20", pdst=f"10.42.0.{50 + index}")
                packet.time = 1000 + index * 0.1
                writer.write(packet)
        result = replay_capture(path, load_devices(AGENT_DIR / "fixtures/devices.json"),
                                Storage(self.directory / "early-state"), armed=True, detector="ml")
        self.assertEqual(result.events, [])
        self.assertEqual(result.agent.enforcer.calls, [])
