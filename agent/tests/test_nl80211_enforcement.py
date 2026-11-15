"""NetworkManager/wpa_supplicant hotspots: no hostapd, stations controlled with iw."""
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "agent"), str(ROOT)]
from securiot_agent.linux_enforcement import LinuxConfig, LinuxEnforcer
from securiot_agent.live import LivePump
from securiot_agent.models import Device
from test_linux_enforcement import ADMIN, MAC, Machine

PHONE = "02:00:00:00:00:30"


class WifiMachine(Machine):
    """Adds `iw` to the command fake; hostapd_cli does not exist on this AP."""
    def __init__(self):
        super().__init__()
        self.stations = {MAC, PHONE}
        self.kicks = []
        self.ap_mode = True

    def __call__(self, args, **options):
        if args[0] == "hostapd_cli":
            raise AssertionError("nl80211 mode must never call hostapd_cli")
        if args[:2] == ["iw", "dev"]:
            self.calls.append((args, None))
            if args[3:] == ["info"]:
                return SimpleNamespace(returncode=0, stdout=f"Interface {args[2]}\n\ttype {'AP' if self.ap_mode else 'managed'}\n")
            if args[3:] == ["station", "dump"]:
                return SimpleNamespace(returncode=0, stdout="".join(f"Station {m} (on {args[2]})\n\tinactive time:\t10 ms\n" for m in sorted(self.stations)))
            if args[3:5] == ["station", "del"]:
                self.kicks.append(args[5])
                self.stations.discard(args[5])
                return SimpleNamespace(returncode=0, stdout="")
        return super().__call__(args, **options)


CONFIG = {"ap_interface": "ap0", "wan_interface": "eth0", "wifi_control": "nl80211", "protected_macs": [ADMIN]}


@pytest.fixture
def wifi(tmp_path, monkeypatch):
    monkeypatch.setattr("securiot_agent.linux_enforcement.platform.system", lambda: "Linux")
    monkeypatch.setattr("securiot_agent.linux_enforcement.os.geteuid", lambda: 0)
    monkeypatch.setattr("securiot_agent.linux_enforcement.time.sleep", lambda _: None)
    monkeypatch.setenv("SECURIOT_REAL_ENFORCEMENT", "yes")
    devices = [Device(MAC, "10.42.0.20", "Pi", simulated=False), Device(PHONE, "10.42.0.30", "Phone", simulated=False),
               Device(ADMIN, "10.42.0.2", "Controller", protected=True, simulated=False)]
    machine = WifiMachine()
    backend = LinuxEnforcer(LinuxConfig(CONFIG), tmp_path / "state", devices, run=machine)
    try:
        yield SimpleNamespace(machine=machine, backend=backend, devices=devices, path=tmp_path / "state")
    finally:
        backend.close()


def test_config_accepts_nl80211_without_hostapd_paths_and_rejects_mixtures():
    assert LinuxConfig(CONFIG).wifi_control == "nl80211"
    with pytest.raises(ValueError):
        LinuxConfig({**CONFIG, "wifi_control": "hostapd"})
    with pytest.raises(ValueError):
        LinuxConfig({**CONFIG, "hostapd_control": "/run/hostapd"})
    with pytest.raises(ValueError):
        LinuxConfig({**CONFIG, "protected_macs": []})


def test_preflight_requires_ap_mode(tmp_path, monkeypatch):
    monkeypatch.setattr("securiot_agent.linux_enforcement.platform.system", lambda: "Linux")
    monkeypatch.setattr("securiot_agent.linux_enforcement.os.geteuid", lambda: 0)
    machine = WifiMachine()
    machine.ap_mode = False
    with pytest.raises(ValueError, match="AP mode"):
        LinuxEnforcer(LinuxConfig(CONFIG), tmp_path / "state", [], run=machine)


def test_quarantine_drops_traffic_and_kicks_station_then_restore_releases(wifi):
    wifi.backend.apply("quarantine", MAC)
    script = next(s for a, s in reversed(wifi.machine.calls) if a == ["nft", "-f", "-"])
    assert "ether saddr @quarantine counter drop" in script and MAC in script
    assert wifi.machine.kicks == [MAC] and MAC not in wifi.machine.stations
    assert wifi.backend.restrictions == {MAC: "quarantined"}
    assert PHONE in wifi.machine.stations, "other clients are untouched"

    wifi.backend.apply("restore", MAC)
    assert wifi.backend.restrictions == {} and wifi.backend.state["owned_deny"] == []
    wifi.machine.stations.add(MAC)  # device rejoins after restore
    assert wifi.backend.maintain() == [] and MAC in wifi.machine.stations


def test_rejoining_quarantined_station_is_kicked_again(wifi):
    wifi.backend.apply("quarantine", MAC)
    wifi.machine.stations.add(MAC)  # rejoins: no deny list on this AP
    assert wifi.backend.maintain() == [MAC]
    assert MAC not in wifi.machine.stations
    assert wifi.backend.maintain() == []


def test_protected_controller_is_never_kicked(wifi):
    with pytest.raises(ValueError, match="Protected"):
        wifi.backend.apply("quarantine", ADMIN)
    assert ADMIN not in wifi.machine.kicks


def test_panic_clears_firewall_and_stops_rekicks(wifi):
    wifi.backend.apply("quarantine", MAC)
    wifi.backend.panic()
    assert not wifi.machine.tables and wifi.backend.state["owned_deny"] == []
    wifi.machine.stations.add(MAC)
    assert wifi.backend.maintain() == []


def test_restart_keeps_quarantine_and_rekicks(wifi, tmp_path):
    wifi.backend.apply("quarantine", MAC)
    wifi.backend.close()
    wifi.machine.stations.add(MAC)
    restarted = LinuxEnforcer(LinuxConfig(CONFIG), wifi.path, wifi.devices, run=wifi.machine)
    try:
        restarted.reconcile()
        assert restarted.restrictions == {MAC: "quarantined"} and MAC not in wifi.machine.stations
    finally:
        restarted.close()


def test_live_loop_runs_upkeep_about_once_a_second(wifi):
    from securiot_agent.detection import DemoDetector
    from securiot_agent.inventory import Inventory
    from securiot_agent.runtime import Agent
    from securiot_agent.simulation import DemoClock
    from securiot_agent.storage import Storage
    from securiot_agent.collector import TrafficCollector

    agent = Agent(Inventory(wifi.devices), DemoDetector(), wifi.backend, Storage(wifi.path, "linux"), clock=DemoClock(1000))
    wifi.backend.apply("quarantine", MAC)
    pump = LivePump(agent, TrafficCollector(agent.inventory.devices))
    wifi.machine.stations.add(MAC)
    pump.step(10.0, wait=0)
    assert MAC not in wifi.machine.stations
    wifi.machine.stations.add(MAC)
    pump.step(10.5, wait=0)
    assert MAC in wifi.machine.stations, "not more than once a second"
    pump.step(11.0, wait=0)
    assert MAC not in wifi.machine.stations
