"""Synthetic threat/normal-lookalike matrix, not a real-world accuracy benchmark."""
from pathlib import Path
import sys
import tempfile

import pytest
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.utils import PcapWriter

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "agent"), str(ROOT)]
from securiot_agent.models import Observation
from securiot_agent.replay import load_devices, replay_capture
from securiot_agent.ml_adapter import MLAdapter
from securiot_agent.simulation import DemoClock

MAC = "02:00:00:00:00:20"
ROUTER = "02:00:00:00:00:01"


def arp(target, source=MAC, op=1):
    return Ether(src=source, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=op, hwsrc=source, psrc="10.42.0.20", pdst=f"10.42.0.{target}")


def syn(host=50, port=80, source=MAC, flags="S"):
    return Ether(src=source, dst=ROUTER) / IP(src="10.42.0.20", dst=f"10.42.0.{host}") / TCP(
        sport=40000, dport=port, flags=flags)


def run(packets, *, armed=True, decoys=(), protected=False, interval=0.05):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "traffic.pcap"
        baseline = syn(flags="A")
        baseline.time = 1000
        with PcapWriter(str(path), sync=True) as writer:
            writer.write(baseline)
            for index, packet in enumerate(packets):
                packet.time = 1032 + interval * index
                writer.write(packet)
        inventory = load_devices(ROOT / "agent/fixtures/devices.json")
        inventory.get(MAC).protected = protected
        from securiot_agent.storage import Storage
        return replay_capture(path, inventory, Storage(Path(directory) / "state"), armed=armed,
                              detector="ml", decoy_ips=decoys)


@pytest.mark.parametrize("count", [0, 1, 10, 29, 30, 45, 100])
def test_multi_host_arp_thresholds(count):
    result = run([arp(50 + index % 40) for index in range(count)])
    assert bool(result.events) == (count >= 30)
    assert bool(result.agent.enforcer.calls) == (count >= 30)


@pytest.mark.parametrize("targets", [1, 2, 7, 8, 15, 30])
def test_arp_quantity_requires_multi_host_evidence_for_containment(targets):
    result = run([arp(50 + index % targets) for index in range(40)])
    assert result.events
    assert bool(result.agent.enforcer.calls) == (targets >= 8)
    if targets < 8:
        assert all(e.evidence["decision"] == "supporting_evidence_only" for e in result.events)


@pytest.mark.parametrize("count", [19, 20, 21, 40])
@pytest.mark.parametrize("vary", ["host", "port"])
def test_host_and_port_scans_are_advisory(count, vary):
    packets = [syn(host=50 + i if vary == "host" else 50, port=1000 + i if vary == "port" else 80)
               for i in range(count)]
    result = run(packets)
    assert bool(result.events) == (count >= 20)
    assert not result.agent.enforcer.calls
    assert all(e.evidence["decision"] == "supporting_evidence_only" for e in result.events)


@pytest.mark.parametrize("flags", ["A", "SA", "R", "F", "PA"])
def test_responses_and_non_syn_packets_do_not_become_scan_attempts(flags):
    result = run([syn(host=50 + i, flags=flags) for i in range(30)])
    assert not result.events
    assert not result.agent.enforcer.calls


def test_retransmissions_do_not_multiply_distinct_targets():
    result = run([syn() for _ in range(100)])
    assert not result.events


@pytest.mark.parametrize("port", [23, 2323, 80, 445, 8080, 443])
@pytest.mark.parametrize("armed", [False, True])
def test_explicit_decoy_single_hit_and_learning_mode(port, armed):
    result = run([syn(host=51, port=port)], decoys=["10.42.0.51"], armed=armed)
    assert result.events[0].evidence["finding"] == "decoy_touch"
    assert result.events[0].actions_taken == (["quarantine"] if armed else [])
    assert result.events[0].would_have == ([] if armed else ["quarantine"])


def test_unconfigured_destination_is_not_automatically_a_decoy():
    assert not run([syn(host=51, port=23)]).events


@pytest.mark.parametrize("kind", ["arp", "decoy", "targets"])
def test_protected_devices_remain_visible_without_enforcement(kind):
    packets = [arp(50 + i) for i in range(30)] if kind == "arp" else (
        [syn(host=51, port=23)] if kind == "decoy" else [syn(host=50 + i) for i in range(20)])
    result = run(packets, protected=True, decoys=["10.42.0.51"] if kind == "decoy" else [])
    assert result.events
    assert not result.agent.enforcer.calls
    assert result.agent.inventory.get(MAC).status == "normal"


@pytest.mark.parametrize("kind", ["arp", "targets"])
def test_slow_scans_are_documented_coverage_gaps(kind):
    packets = [arp(50 + i) for i in range(30)] if kind == "arp" else [syn(host=50 + i) for i in range(20)]
    result = run(packets, interval=2)
    assert not result.events  # Known blind spot: not evidence that the traffic is benign.


@pytest.mark.parametrize("kind", ["syn_flood", "udp_flood", "arp_replies", "dns_beacon"])
def test_unimplemented_attack_families_are_not_claimed_as_detected(kind):
    if kind == "syn_flood":
        packets = [syn() for _ in range(100)]
    elif kind == "arp_replies":
        packets = [arp(50 + i % 30, op=2) for i in range(100)]
    elif kind == "dns_beacon":
        packets = [Ether(src=MAC, dst=ROUTER) / IP(dst="10.42.0.1") / UDP(dport=53)
                   / DNS(qd=DNSQR(qname=f"{i}.beacon.example.test")) for i in range(50)]
    else:
        packets = [Ether(src=MAC, dst=ROUTER) / IP(dst="10.42.0.1") / UDP(dport=123) for _ in range(100)]
    assert not run(packets).events  # Explicit unsupported cases, not an accuracy success claim.


@pytest.mark.parametrize("nbytes,expected", [(1000, False), (1399, False), (1400, True), (1800, True)])
def test_volume_signal_feature_level_only(nbytes, expected):
    clock = DemoClock(1000)
    adapter = MLAdapter(clock)
    adapter.detector.baselines = {MAC.upper(): {"mean": 1000, "std": 100}}
    clock.advance(31)
    result = adapter.observe(Observation(MAC, bytes_out=nbytes))
    assert bool(result) == expected
    if result:
        assert result.kind == "volume"
        assert not result.containment_allowed


def test_decoy_signal_can_override_ambiguous_arp_quantity():
    clock = DemoClock(1000)
    adapter = MLAdapter(clock)
    clock.advance(31)
    result = adapter.observe(Observation(MAC, packet_arp_requests=35, arp_targets=("10.42.0.1",),
                                        packet_decoy_hits=(23,)))
    assert result.kind == "decoy_touch" and result.containment_allowed


@pytest.mark.parametrize("bad", [{"kind": "attack"}, "attack", 1])
def test_model_adapter_cannot_trigger_actions_with_untyped_results(bad):
    from securiot_agent.enforcement import MockEnforcer
    from securiot_agent.inventory import Inventory
    from securiot_agent.models import Device
    from securiot_agent.runtime import Agent
    from securiot_agent.storage import Storage
    class InvalidDetector:
        def observe(self, observation):
            return bad
    with tempfile.TemporaryDirectory() as directory:
        backend = MockEnforcer()
        agent = Agent(Inventory([Device(MAC, "10.42.0.20", "test")]), InvalidDetector(), backend,
                      Storage(Path(directory)), clock=DemoClock(1000))
        with pytest.raises(ValueError):
            agent.observe(Observation(MAC))
        assert not backend.calls


@pytest.mark.parametrize("value", ["not-an-ip", "10.42.0.999", "https://example.com"])
def test_invalid_decoy_configuration_fails_instead_of_silently_disabling_detection(value):
    from securiot_agent.collector import TrafficCollector
    with pytest.raises(ValueError):
        TrafficCollector([MAC], decoy_ips=[value])
