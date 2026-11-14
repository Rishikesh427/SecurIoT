"""Packet-level and end-to-end replay tests; requires the optional replay extra."""

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

AGENT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(AGENT_DIR))

HAS_SCAPY = importlib.util.find_spec("scapy") is not None
if HAS_SCAPY:
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.inet6 import IPv6, IPv6ExtHdrHopByHop
    from scapy.layers.l2 import ARP, Dot1Q, Ether
    from scapy.packet import Raw
    from scapy.utils import PcapNgWriter, PcapWriter

    from securiot_agent.collector import TrafficCollector
    from securiot_agent.detection import ReplayPreviewDetector
    from securiot_agent.packets import CaptureStats, decode_packet, read_capture
    from securiot_agent.replay import load_devices, replay_capture
    from securiot_agent.storage import Storage

CAMERA = "02:00:00:00:00:20"
LAPTOP = "02:00:00:00:00:02"
ROUTER = "02:00:00:00:00:01"


@unittest.skipUnless(HAS_SCAPY, "Install the agent[replay] extra to run packet tests")
class PacketReplayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def packet(self, timestamp, *, host=50, flags="S", source=CAMERA):
        packet = Ether(src=source, dst=ROUTER) / IP(src="10.42.0.20", dst=f"10.42.0.{host}") / TCP(
            sport=40000, dport=80, flags=flags)
        packet.time = timestamp
        return packet

    def capture(self, packets, *, pcapng=False):
        path = self.directory / ("packets.pcapng" if pcapng else "packets.pcap")
        writer_type = PcapNgWriter if pcapng else PcapWriter
        with writer_type(str(path)) as writer:
            for packet in packets:
                writer.write(packet)
        return path

    def replay(self, packets, *, armed=False):
        return replay_capture(self.capture(packets), load_devices(AGENT_DIR / "fixtures/devices.json"),
                              Storage(self.directory / "state"), armed=armed)

    def test_ethernet_identity_is_used_instead_of_arp_claimed_identity(self):
        packet = Ether(src=CAMERA, dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=1, hwsrc=LAPTOP, psrc="10.42.0.20", pdst="10.42.0.1")
        record = decode_packet(packet)
        self.assertEqual(record.source_mac, CAMERA)
        self.assertTrue(record.arp_request)
        self.assertEqual(record.captured_bytes, len(packet))

    def test_dns_queries_are_normalized_and_replies_are_excluded(self):
        packet = Ether(src=CAMERA, dst=ROUTER) / IP(dst="10.42.0.1") / UDP(dport=53) / DNS(
            qr=0, qd=DNSQR(qname="Camera.Example.Test."))
        self.assertEqual(decode_packet(packet).dns_queries, ("camera.example.test",))
        packet[DNS].qr = 1
        self.assertEqual(decode_packet(packet).dns_queries, ())

    def test_syn_ack_and_quoted_tcp_headers_do_not_count_as_attempts(self):
        self.assertIsNone(decode_packet(self.packet(1000, flags="SA")).syn_target)
        quoted = Ether(src=CAMERA, dst=ROUTER) / IP(dst="10.42.0.1") / ICMP(type=3) / IP(
            dst="10.42.0.50") / TCP(dport=80, flags="S")
        self.assertIsNone(decode_packet(quoted).syn_target)

    def test_vlan_and_ipv6_headers_are_decoded(self):
        packet = Ether(src=CAMERA, dst=ROUTER) / Dot1Q(vlan=7) / IP(dst="10.42.0.50") / TCP(
            dport=445, flags="S")
        self.assertEqual(decode_packet(packet).syn_target, ("10.42.0.50", 445))
        ipv6 = Ether(src=CAMERA, dst=ROUTER) / IPv6(dst="2001:db8::1") / IPv6ExtHdrHopByHop() / TCP(
            dport=80, flags="S")
        self.assertEqual(decode_packet(ipv6).syn_target, ("2001:db8::1", 80))

    def test_non_initial_ip_fragments_are_not_treated_as_connection_attempts(self):
        packet = self.packet(1000)
        packet[IP].frag = 1
        self.assertIsNone(decode_packet(packet).syn_target)

    def test_packet_byte_deltas_do_not_double_count_rolling_window_totals(self):
        packets = [self.packet(1000 + i) for i in range(3)]
        response = Ether(src=ROUTER, dst=CAMERA) / IP(dst="10.42.0.20") / TCP(flags="SA")
        response.time = 1003
        result = self.replay(packets + [response])
        camera = result.agent.inventory.get(CAMERA)
        self.assertEqual(camera.bytes_out, sum(len(packet) for packet in packets))
        self.assertEqual(camera.bytes_in, len(response))
        self.assertEqual(result.events, [])

    def test_exact_sliding_window_boundary_and_expiry(self):
        collector = TrafficCollector([CAMERA])
        for i in range(19):
            collector.consume(decode_packet(self.packet(1000, host=50 + i)))
        at_boundary = collector.consume(decode_packet(self.packet(1010, host=69)))[0]
        self.assertEqual(len(at_boundary.syn_targets), 20)
        after_boundary = collector.consume(decode_packet(self.packet(1010.001, host=70)))[0]
        self.assertEqual(len(after_boundary.syn_targets), 2)

    def test_traffic_from_different_devices_is_not_combined(self):
        collector = TrafficCollector([CAMERA, LAPTOP])
        for i in range(19):
            collector.consume(decode_packet(self.packet(1000 + i * 0.1, host=50 + i)))
        laptop = collector.consume(decode_packet(self.packet(1002, source=LAPTOP)))[0]
        self.assertEqual(len(laptop.syn_targets), 1)
        self.assertIsNone(ReplayPreviewDetector().observe(laptop))

    def test_one_finding_is_emitted_on_crossing_then_rearms_after_window_expires(self):
        packets = [self.packet(1000)]
        packets += [self.packet(1032 + i * 0.1, host=50 + i) for i in range(25)]
        packets += [self.packet(1050)]
        packets += [self.packet(1051 + i * 0.1, host=50 + i) for i in range(20)]
        result = self.replay(packets)
        self.assertEqual(len(result.events), 2)
        self.assertTrue(all(event.would_have == ["quarantine"] for event in result.events))
        self.assertTrue(all(event.evidence["detection"]["input"] == "packet_capture" for event in result.events))

    def test_early_scan_is_found_but_startup_warmup_prevents_action(self):
        result = self.replay([self.packet(1000 + i * 0.1, host=50 + i) for i in range(20)], armed=True)
        self.assertEqual(len(result.events), 1)
        self.assertEqual(result.events[0].evidence["decision"], "startup_warmup")
        self.assertEqual(result.agent.enforcer.calls, [])

    def test_continuing_scan_is_reconsidered_after_warmup(self):
        # Never drop below threshold: there is no new crossing after warmup.
        sustained = [self.packet(2000, host=50 + i) for i in range(20)]
        sustained += [self.packet(2000 + i * 0.25, host=50 + i % 100) for i in range(1, 141)]
        result = replay_capture(self.capture(sustained), load_devices(AGENT_DIR / "fixtures/devices.json"),
                                Storage(self.directory / "sustained-state"), armed=True)
        self.assertEqual(result.agent.inventory.get(CAMERA).status, "quarantined")
        self.assertEqual(result.agent.enforcer.calls, [("quarantine", CAMERA)])
        self.assertTrue(any(e.evidence["decision"] == "startup_warmup" for e in result.events))
        self.assertTrue(any(e.actions_taken == ["quarantine"] for e in result.events))

    def test_generated_fixtures_have_distinct_expected_behaviors(self):
        for filename, expected_count, expected_decision in [
            ("normal.pcap", 0, None),
            ("slow_targets.pcap", 0, None),
            ("scan.pcap", 1, "applied_to_simulated_device"),
            ("protected_arp.pcap", 1, "protected_device"),
        ]:
            with self.subTest(filename=filename):
                result = replay_capture(
                    AGENT_DIR / "fixtures" / filename, load_devices(AGENT_DIR / "fixtures/devices.json"),
                    Storage(self.directory / filename), armed=True,
                )
                self.assertEqual(len(result.events), expected_count)
                if expected_count:
                    self.assertEqual(result.events[0].evidence["decision"], expected_decision)
                if filename == "scan.pcap":
                    self.assertEqual(result.agent.inventory.get(CAMERA).status, "quarantined")
                    self.assertIn("camera.example.test", result.agent.inventory.get(CAMERA).dns_queries)
                    self.assertEqual(result.events[0].evidence["detection"]["unique_syn_targets"], 20)
                    self.assertEqual(result.events[0].evidence["detection"]["captured_at"], 1700000033.9)

    def test_unconfigured_mac_is_counted_without_becoming_actionable(self):
        result = self.replay([self.packet(1000, source="02:00:00:00:00:99")])
        self.assertEqual(result.collector.unmatched_frames, 1)
        self.assertEqual(result.events, [])
        self.assertEqual(result.agent.enforcer.calls, [])
        self.assertIsNone(result.agent.inventory.get("02:00:00:00:00:99"))

    def test_pcapng_is_read_through_the_same_pipeline(self):
        path = self.capture([self.packet(1000), self.packet(1031)], pcapng=True)
        stats = CaptureStats()
        self.assertEqual(len(list(read_capture(path, stats))), 2)
        self.assertEqual(stats.ethernet_frames, 2)

    def test_broken_capture_and_out_of_order_timestamps_fail_clearly(self):
        path = self.directory / "broken.pcap"
        path.write_bytes(b"this is not a packet capture")
        with self.assertRaisesRegex(ValueError, "Cannot read capture"):
            list(read_capture(path))
        unordered = self.capture([self.packet(1001), self.packet(1000)])
        with self.assertRaisesRegex(ValueError, "out of order"):
            list(read_capture(unordered))

    def test_unsupported_link_layer_is_not_assigned_invented_macs(self):
        path = self.directory / "raw-ip.pcap"
        with PcapWriter(str(path), linktype=101) as writer:
            writer.write(bytes(IP(dst="192.0.2.1") / TCP(flags="S")))
        with self.assertRaisesRegex(ValueError, "no supported Ethernet"):
            list(read_capture(path))
        self.assertIsNone(decode_packet(Raw(b"short")))

    def test_window_capacity_stops_instead_of_silently_undercounting(self):
        collector = TrafficCollector([CAMERA], max_window_packets=1)
        collector.consume(decode_packet(self.packet(1000)))
        with self.assertRaisesRegex(ValueError, "rather than undercounting"):
            collector.consume(decode_packet(self.packet(1001)))

    def test_bad_device_configuration_is_rejected(self):
        path = self.directory / "devices.json"
        path.write_text(json.dumps({"devices": [
            {"mac": CAMERA, "ip": "10.42.0.20", "name": "Camera", "protected": "false"},
        ]}))
        with self.assertRaisesRegex(ValueError, "protected must be"):
            load_devices(path)

    def test_replay_command_line_stays_safe_by_default(self):
        result = subprocess.run([
            sys.executable, str(AGENT_DIR / "agent.py"), "--replay", str(AGENT_DIR / "fixtures/scan.pcap"),
            "--state-dir", str(self.directory / "cli-state"),
        ], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Scan findings: 1", result.stdout)
        self.assertIn("would have: quarantine", result.stdout)
        self.assertIn("Camera (generated fixture): normal", result.stdout)


if __name__ == "__main__":
    unittest.main()
