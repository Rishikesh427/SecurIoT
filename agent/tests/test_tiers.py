from securiot_agent.models import Device, Finding
from securiot_agent.inventory import Inventory
from securiot_agent.enforcement import MockEnforcer
from securiot_agent.runtime import Agent
from securiot_agent.storage import Storage
from securiot_agent.detection import DemoDetector

MAC = "02:00:00:00:00:30"


def make(tmp_path):
    inventory = Inventory([Device(MAC, "10.42.0.30", "t")])
    return Agent(inventory, DemoDetector(), MockEnforcer(), Storage(tmp_path), clock=lambda: 1000.0)


def finding(kind, score):
    return Finding(kind, {"anomaly": score})


def test_tiers(tmp_path):
    agent = make(tmp_path)
    assert agent.choose_action(MAC, finding("scan_arp", 0.96)) is None
    assert agent.choose_action(MAC, finding("scan_arp", 0.97)) == "block_wan"
    assert agent.choose_action(MAC, finding("scan_arp", 0.99)) == "quarantine"
    assert agent.choose_action(MAC, finding("decoy_touch", 0)) == "quarantine"


def test_continuing_scan_after_block_escalates(tmp_path):
    agent = make(tmp_path)
    agent.inventory.get(MAC).status = "blocked"
    assert agent.choose_action(MAC, finding("scan_arp", 0.97)) == "quarantine"


def test_policy_fallback(tmp_path):
    agent = make(tmp_path)
    agent.ladder["quarantine"] = False
    assert agent.choose_action(MAC, finding("decoy_touch", 0)) == "block_wan"
    agent.ladder["block_wan"] = False
    assert agent.choose_action(MAC, finding("decoy_touch", 0)) is None


def test_unscored_finding_still_contains(tmp_path):
    agent = make(tmp_path)
    assert agent.choose_action(MAC, Finding("scan", {})) == "quarantine"