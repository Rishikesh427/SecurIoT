"""Failure/restart and dashboard-to-Linux-backend contract tests, without host changes."""
import json
from pathlib import Path
import re
import subprocess
import sys
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "agent"), str(ROOT)]
from api.settings import Settings
from api.main import create_app
from securiot_agent.cloud import CloudError
from securiot_agent.cloud_loop import CloudLoop
from securiot_agent.detection import DemoDetector
from securiot_agent.inventory import Inventory
from securiot_agent.linux_enforcement import EnforcementError, LinuxConfig, LinuxEnforcer, OWNER, TABLE
from securiot_agent.models import Device, Finding
from securiot_agent.runtime import Agent
from securiot_agent.simulation import DemoClock
from securiot_agent.storage import Storage
from securiot_agent.vulnerabilities import VulnerabilityAssessor

MAC = "02:00:00:00:00:20"
ADMIN = "02:00:00:00:00:02"
OTHER = "02:00:00:00:00:30"


class Machine:
    """Small command-boundary fake; kernel packet behavior is tested separately."""
    def __init__(self):
        self.denied, self.stations, self.tables = set(), {MAC}, {}
        self.calls = []
        self.fail = None
        self.ignore = None
        self.bridge = False
        self.flowtable = False
        self.authorized = True
        self.keep_station = False

    def __call__(self, args, **options):
        self.calls.append((args, options.get("input")))
        output, code = "", 0
        operation = args[0] if args[0] != "hostapd_cli" else " ".join(args[5:])
        if args[:3] == ["nft", "-f", "-"]:
            operation = "nft_apply"
        if self.fail == operation:
            return SimpleNamespace(returncode=0 if args[0] == "hostapd_cli" else 1, stdout="FAIL")
        if args[0] == "ip":
            ap = {"ifname":"ap0","address":"02:00:00:00:01:01"}
            if self.bridge:
                ap["master"] = "br0"
            output = json.dumps([ap, {"ifname":"eth0","address":"02:00:00:00:01:02"}])
        elif args[:4] == ["nft", "-j", "list", "ruleset"]:
            items = [{"table":{"family":family,"name":name,"comment":comment}} for (family,name),comment in self.tables.items()]
            if self.flowtable:
                items.append({"flowtable":{"name":"fastpath"}})
            output = json.dumps({"nftables":items})
        elif operation == "nft_apply":
            script = options["input"]
            for family in ("inet", "netdev"):
                if f"delete table {family} {TABLE}" in script:
                    self.tables.pop((family,TABLE),None)
                if re.search(rf"(?m)^table {family} {TABLE} ",script):
                    self.tables[(family,TABLE)] = OWNER
        elif args[0] == "hostapd_cli":
            cmd = args[5:]
            if cmd == ["ping"]:
                output = "PONG"
            elif cmd == ["deny_acl","SHOW"]:
                output = "\n".join(sorted(self.denied))
            elif cmd == ["sta",MAC]:
                output = MAC + "\nflags=" + ("[AUTH][ASSOC][AUTHORIZED]" if self.authorized else "[AUTH]")
            elif cmd == ["all_sta"]:
                output = "\n".join(sorted(self.stations))
            else:
                output = "OK"
                if self.ignore != operation:
                    if cmd[:2] == ["deny_acl","ADD_MAC"]:
                        self.denied.add(cmd[2])
                    elif cmd[:2] == ["deny_acl","DEL_MAC"]:
                        self.denied.discard(cmd[2])
                    elif cmd[0] == "deauthenticate":
                        self.authorized = False
                        if not self.keep_station:
                            self.stations.discard(cmd[1])
        return SimpleNamespace(returncode=code, stdout=output)


@pytest.fixture
def lab(tmp_path, monkeypatch):
    monkeypatch.setattr("securiot_agent.linux_enforcement.platform.system", lambda: "Linux")
    monkeypatch.setattr("securiot_agent.linux_enforcement.os.geteuid", lambda: 0)
    monkeypatch.setenv("SECURIOT_REAL_ENFORCEMENT","yes")
    monkeypatch.setattr("securiot_agent.linux_enforcement.time.sleep", lambda _: None)
    conf = tmp_path / "hostapd.conf"
    conf.write_text("interface=ap0\nctrl_interface=/run/hostapd\nmacaddr_acl=0\n")
    config = LinuxConfig({"ap_interface":"ap0","wan_interface":"eth0","hostapd_control":"/run/hostapd",
                          "hostapd_config":str(conf),"protected_macs":[ADMIN]})
    devices = [Device(MAC,"10.42.0.20","Pi",simulated=False), Device(ADMIN,"10.42.0.2","Controller",protected=True,simulated=False)]
    machine = Machine()
    backend = LinuxEnforcer(config,tmp_path / "state",devices,run=machine)
    try:
        yield SimpleNamespace(config=config,devices=devices,machine=machine,backend=backend,path=tmp_path / "state")
    finally:
        backend.close()


def make_agent(lab):
    return Agent(Inventory(lab.devices),DemoDetector(),lab.backend,Storage(lab.path,"linux"),clock=DemoClock(1000))


def test_quarantine_restore_are_verified_idempotent_and_preserve_unrelated_state(lab):
    lab.machine.tables[("inet","unrelated")] = "administrator"
    lab.machine.denied.add(OTHER)
    lab.backend.reconcile()
    lab.backend.apply("quarantine",MAC)
    assert MAC in lab.machine.denied and MAC not in lab.machine.stations
    assert lab.backend.restrictions == {MAC:"quarantined"}
    lab.backend.apply("quarantine",MAC)
    lab.backend.apply("restore",MAC)
    lab.backend.apply("restore",MAC)
    assert lab.machine.denied == {OTHER} and lab.backend.restrictions == {}
    assert lab.machine.tables[("inet","unrelated")] == "administrator"
    assert all("flush ruleset" not in (script or "") for _,script in lab.machine.calls)
    assert not lab.backend.state["pending"]


def test_wan_block_has_both_directions_and_quarantine_covers_arp_ipv6(lab):
    lab.backend.apply("block_wan",MAC)
    script = next(script for args,script in reversed(lab.machine.calls) if args == ["nft","-f","-"])
    assert 'iifname "ap0" oifname "eth0" ether saddr @wan_blocked' in script
    assert 'meta iifname "eth0" ether daddr @wan_blocked' in script
    assert 'hook ingress device "ap0"' in script and 'hook egress device "ap0"' in script
    assert "ether saddr @quarantine" in script and "ether daddr @quarantine" in script
    assert "ip saddr" not in script  # MAC/inet rules cover both IP families, including address changes.
    assert MAC not in lab.machine.denied and MAC in lab.machine.stations


@pytest.mark.parametrize("mac",[ADMIN,"ff:ff:ff:ff:ff:ff","01:00:00:00:00:20","bad; reboot",OTHER])
def test_unknown_protected_and_invalid_targets_never_change_firewall(lab,mac):
    lab.machine.calls.clear()
    with pytest.raises(ValueError):
        lab.backend.apply("quarantine",mac)
    assert not lab.machine.calls


@pytest.mark.parametrize("failure",["nft_apply",f"deny_acl ADD_MAC {MAC}",f"deauthenticate {MAC}"])
def test_failure_retains_intent_and_restart_reconciles_without_claiming_success(lab,failure):
    lab.machine.fail = failure
    with pytest.raises(EnforcementError):
        lab.backend.apply("quarantine",MAC)
    assert lab.backend.restrictions == {}
    assert json.loads((lab.path / "enforcement.json").read_text())["pending"]
    lab.backend.close()
    lab.machine.fail = None
    restarted = LinuxEnforcer(lab.config,lab.path,lab.devices,run=lab.machine)
    try:
        restarted.reconcile()
        assert restarted.restrictions == {MAC:"quarantined"}
        assert MAC in lab.machine.denied and MAC not in lab.machine.stations
    finally:
        restarted.close()


@pytest.mark.parametrize("ignored",[f"deny_acl ADD_MAC {MAC}",f"deauthenticate {MAC}"])
def test_hostapd_ok_without_effect_is_not_success(lab,ignored):
    lab.machine.ignore = ignored
    with pytest.raises(EnforcementError):
        lab.backend.apply("quarantine",MAC)
    assert lab.backend.restrictions == {} and lab.backend.state["pending"]


def test_failed_restore_retains_last_confirmed_status_and_retry_recovers(lab):
    agent = make_agent(lab)
    agent.set_armed(True)
    assert agent.request_action("quarantine",MAC,manual=True).actions_taken
    lab.machine.fail = f"deny_acl DEL_MAC {MAC}"
    event = agent.request_action("restore",MAC,manual=True)
    assert not event.actions_taken and event.evidence["enforcement_uncertain"]
    assert agent.inventory.get(MAC).status == "quarantined"
    lab.machine.fail = None
    assert agent.request_action("restore",MAC,manual=True).actions_taken == ["restore"]
    assert agent.inventory.get(MAC).status == "normal"


def test_local_panic_clears_owned_entries_and_stale_runtime_state_cannot_reapply(lab):
    agent = make_agent(lab)
    agent.set_armed(True)
    agent.request_action("quarantine",MAC,manual=True)
    lab.machine.denied.add(OTHER)
    lab.machine.tables[("inet","other")] = "other"
    lab.backend.panic()
    assert lab.machine.denied == {OTHER}
    assert lab.machine.tables == {("inet","other"):"other"}
    restarted = make_agent(lab)
    assert restarted.inventory.get(MAC).status == "normal"
    assert restarted.policy.learning_mode


def test_panic_does_not_require_working_ap_config_and_does_not_reapply_pending_ban(lab):
    lab.backend.apply("quarantine",MAC)
    lab.backend.close()
    Path(lab.config.hostapd_config).unlink()
    backend = LinuxEnforcer(lab.config,lab.path,lab.devices,run=lab.machine,recovery=True)
    try:
        backend.panic()
        assert backend.restrictions == {} and MAC not in lab.machine.denied
    finally:
        backend.close()


def test_panic_records_unfinished_deny_cleanup_but_clears_firewall_first(lab):
    lab.backend.apply("quarantine",MAC)
    lab.machine.fail = f"deny_acl DEL_MAC {MAC}"
    with pytest.raises(EnforcementError):
        lab.backend.panic()
    assert not lab.machine.tables
    assert lab.backend.state["desired"] == {} and lab.backend.state["pending"]


def test_external_deny_entries_are_never_removed_or_claimed(lab):
    lab.machine.denied.add(MAC)
    with pytest.raises(EnforcementError,match="external"):
        lab.backend.apply("quarantine",MAC)
    with pytest.raises(EnforcementError,match="external"):
        lab.backend.apply("restore",MAC)
    assert MAC in lab.machine.denied and MAC not in lab.backend.state["owned_deny"]


def test_lock_prevents_second_agent_and_live_panic(lab):
    with pytest.raises(BlockingIOError):
        LinuxEnforcer(lab.config,lab.path,lab.devices,run=lab.machine)


@pytest.mark.parametrize("problem",["bridge","flowtable","foreign_table"])
def test_unsupported_topology_or_unowned_table_fails_without_mutation(lab,problem):
    lab.backend.close()
    if problem == "foreign_table":
        lab.machine.tables[("inet",TABLE)] = "someone else"
    else:
        setattr(lab.machine,problem,True)
    lab.machine.calls.clear()
    with pytest.raises((ValueError,EnforcementError)):
        LinuxEnforcer(lab.config,lab.path,lab.devices,run=lab.machine)
    assert not any(args[:2] == ["nft","-f"] for args,_ in lab.machine.calls)


def test_new_local_protection_releases_only_owned_restrictions(lab):
    lab.backend.apply("quarantine",MAC)
    lab.backend.protected.add(MAC)
    lab.backend.reconcile()
    assert not lab.backend.restrictions and MAC not in lab.machine.denied


def test_manual_actions_bypass_automatic_mode_but_preserve_protection_and_policy(lab):
    agent = make_agent(lab)
    assert agent.request_action("quarantine",MAC,manual=True).actions_taken
    agent.request_action("restore",MAC,manual=True)
    agent.set_armed(True)
    assert agent.request_action("quarantine",ADMIN,manual=True).evidence["decision"] == "protected_device"
    assert agent.request_action("quarantine",MAC,manual=True).actions_taken
    agent.request_action("restore",MAC,manual=True)
    assert agent.request_action("quarantine",MAC).evidence["decision"] == "startup_warmup"
    agent.clock.advance(31)
    assert agent.request_action("quarantine",MAC).evidence["decision"] == "restore_grace"
    assert agent.request_action("quarantine",MAC,manual=True).actions_taken
    agent.request_action("restore",MAC,manual=True)
    agent.ladder["quarantine"] = False
    assert agent.request_action("quarantine",MAC,manual=True).evidence["decision"] == "disabled_by_policy"


def test_mock_and_linux_runtime_state_cannot_be_mixed(lab):
    Storage(lab.path).save_state({"version":1,"mode":"simulation","saved_at":0,"devices":{}})
    before = len(lab.machine.calls)
    with pytest.raises(ValueError,match="mode"):
        make_agent(lab)
    assert len(lab.machine.calls) == before


def test_dashboard_quarantine_restore_roundtrip_and_lost_ack_does_not_repeat(lab):
    agent = make_agent(lab)
    assessor = VulnerabilityAssessor()
    for device in lab.devices:
        device.assessment = assessor.assess(device,0)
        device.last_seen = agent.clock()
    config = Settings(database_url="",jwt_secret="test-only-secret-"*3,agent_api_key="test-key",
                      storage_mode="memory",judge_username="judge",judge_password="test-only-password-12345")
    with TestClient(create_app(config)) as http:
        login = http.post("/auth/login",json={"username":"judge","password":config.judge_password})
        headers = {"Authorization":"Bearer " + login.json()["access_token"]}
        class Transport:
            identity = "linux-api-test"
            lose_ack = False
            def request(self,method,path,payload=None,query=None):
                result = http.request(method,path,json=payload,params=query,headers={"X-API-Key":"test-key"})
                if result.status_code not in (200,204,304):
                    raise CloudError(f"HTTP {result.status_code}")
                if path.endswith("/ack") and self.lose_ack:
                    self.lose_ack = False
                    raise CloudError("Accepted ack response lost")
                return result.status_code, result.json() if result.status_code == 200 else None
        transport = Transport()
        loop = CloudLoop(agent,transport,ROOT / "contract/schemas.json",permit_arm=True)
        assert loop.tick() == []
        policy = http.get("/policy",headers=headers)
        http.put("/policy",headers={**headers,"If-Match":policy.headers["ETag"]},json={
            "learning_mode":False,"protected_macs":[ADMIN],"ladder":{"notify":True,"block_wan":True,"quarantine":True}}).raise_for_status()
        action_headers = {**headers,"Idempotency-Key":str(uuid4())}
        command = http.post("/actions",headers=action_headers,json={"action":"quarantine","mac":MAC})
        assert command.status_code == 202
        assert http.post("/actions",headers=action_headers,json={"action":"quarantine","mac":MAC}).json()["id"] == command.json()["id"]
        assert agent.inventory.get(MAC).status == "normal"  # Queueing is not application.
        transport.lose_ack = True
        assert loop.tick()
        assert agent.inventory.get(MAC).status == "quarantined" and MAC in lab.machine.denied
        count = len(lab.machine.calls)
        assert CloudLoop(agent,transport,ROOT / "contract/schemas.json",permit_arm=True).tick() == []
        assert len(lab.machine.calls) == count
        report = next(d for d in http.get("/devices",headers=headers).json() if d["mac"] == MAC)
        assert report["status"] == "quarantined" and not report["simulated"]
        row = next(r for r in http.get("/audit",headers=headers).json() if r.get("command_id") == command.json()["id"])
        assert row["outcome"] == "applied"
        assert http.post("/actions",headers=headers,json={"action":"quarantine","mac":ADMIN}).status_code == 409
        restore = http.post("/actions",headers=headers,json={"action":"restore","mac":MAC})
        assert restore.status_code == 202 and loop.tick() == []
        assert agent.inventory.get(MAC).status == "normal" and MAC not in lab.machine.denied
        assert agent.grace_until[MAC] >= agent.clock()+60


def test_restore_all_includes_a_failed_quarantine_with_normal_last_confirmed_status(lab):
    agent = make_agent(lab)
    agent.set_armed(True)
    lab.machine.fail = f"deny_acl ADD_MAC {MAC}"
    assert not agent.request_action("quarantine",MAC,manual=True).actions_taken
    assert agent.inventory.get(MAC).status == "normal"
    lab.machine.fail = None
    assert agent.request_action("restore_all",manual=True).actions_taken == ["restore_all"]
    assert not lab.backend.restrictions and not lab.backend.pending_macs


def test_real_backend_is_opt_in_and_simulated_devices_are_rejected(lab,monkeypatch):
    monkeypatch.delenv("SECURIOT_REAL_ENFORCEMENT")
    with pytest.raises(ValueError,match="REAL_ENFORCEMENT"):
        make_agent(lab)
    monkeypatch.setenv("SECURIOT_REAL_ENFORCEMENT","yes")
    lab.devices[0].simulated = True
    with pytest.raises(ValueError,match="simulated"):
        make_agent(lab)


def test_live_pump_serializes_packets_and_polls_commands_when_idle(tmp_path):
    from scapy.layers.l2 import Ether
    from scapy.layers.inet import IP,TCP
    from securiot_agent.live import build,LivePump
    agent,collector = build(ROOT / "agent/fixtures/devices.json",tmp_path,clock=DemoClock(1000),armed=True,decoy_ips=["10.42.0.51"])
    agent.clock.advance(31)
    polls,events = [],[]
    class Commands:
        def tick(self):
            polls.append(True)
            return []
    pump = LivePump(agent,collector,Commands(),capacity=1,on_event=events.append)
    packet=Ether(src=MAC,dst=ADMIN)/IP(src="10.42.0.20",dst="10.42.0.51")/TCP(dport=2323,flags="S")
    packet.time=1031
    pump.receive(packet)
    pump.receive(packet)
    assert pump.dropped == 1 and not events and not polls
    pump.step(0,wait=0)
    assert len(events) == 1 and len(polls) == 1
    pump.step(.25,wait=0)
    assert len(polls) == 1
    pump.step(.5,wait=0)
    assert len(polls) == 2


@pytest.mark.parametrize("args",[
    ["--replay","capture.pcap","--enforcement","linux"],
    ["--simulate","--enforcement","linux"],
    ["--live","ap0","--enforcement","linux"],
    ["--panic"],
    ["--live","ap0","--once","--connect"],
])
def test_cli_refuses_ambiguous_real_enforcement_or_replay_to_firewall(args):
    from securiot_agent.cli import main
    with pytest.raises(SystemExit) as error:
        main(args)
    assert error.value.code == 2


def test_cli_passes_live_cloud_options_without_requiring_replay(monkeypatch,tmp_path):
    from securiot_agent.cli import main
    calls=[]
    monkeypatch.setenv('SECURIOT_DISCOVERY_CONFIG','discovery.json')
    monkeypatch.setattr('securiot_agent.linux_enforcement.LinuxConfig.load',lambda path: 'real-config')
    monkeypatch.setenv("AGENT_API_KEY","test-key")
    monkeypatch.setattr("securiot_agent.live.run_live",lambda *args,**kwargs:calls.append((args,kwargs)))
    assert main(["--live","ap0","--enforcement","linux","--enforcement-config","linux.json","--connect","--api-url","http://127.0.0.1:8000", "--state-dir",str(tmp_path),"--arm"]) == 0
    assert calls[0][0][0] == "ap0"
    assert calls[0][1]["api_key"] == "test-key" and calls[0][1]["linux_config"] == "real-config"
    assert calls[0][0][1] is None


@pytest.mark.parametrize("change",[
    {"ap_interface":'ap0"; flush ruleset'},
    {"wan_interface":"ap0"},
    {"protected_macs":[]},
    {"protected_macs":["ff:ff:ff:ff:ff:ff"]},
    {"hostapd_control":"relative/path"},
])
def test_linux_configuration_rejects_unsafe_or_ambiguous_values(lab,change):
    data={**lab.config.identity,"protected_macs":[ADMIN],**change}
    with pytest.raises(ValueError):
        LinuxConfig(data)


def test_panic_cli_does_not_need_a_device_file(lab,monkeypatch):
    from securiot_agent.cli import main
    calls=[]
    class Recovery:
        def __init__(self,config,state,devices,*,recovery=False):
            assert devices == [] and recovery
        def panic(self): calls.append("panic")
        def close(self): calls.append("close")
    monkeypatch.setattr("securiot_agent.linux_enforcement.LinuxConfig.load",lambda path:lab.config)
    monkeypatch.setattr("securiot_agent.linux_enforcement.LinuxEnforcer",Recovery)
    assert main(["--panic","--enforcement","linux","--enforcement-config","/missing/config.json"]) == 0
    assert calls == ["panic","close"]


def test_deauthenticated_station_may_remain_in_hostapd_history_without_authorization(lab):
    lab.machine.keep_station = True
    lab.backend.apply("quarantine",MAC)
    assert MAC in lab.machine.stations and not lab.machine.authorized
    assert lab.backend.restrictions == {MAC:"quarantined"}


def test_discovery_only_restart_preserves_real_block_and_restore(lab, monkeypatch, tmp_path):
    from securiot_agent.live import build
    lab.backend.apply('block_wan', MAC)
    lab.backend.close()
    discovery = tmp_path / 'discovery.json'
    discovery.write_text(json.dumps({'interface':'ap0','cidr':'10.42.0.0/24','protect_guests':False}))
    monkeypatch.setenv('SECURIOT_DISCOVERY_CONFIG',str(discovery))
    (lab.path/'discovered-devices.json').write_text(json.dumps({'devices':[
        {'mac':MAC,'ip':'10.42.0.20','name':'Known restricted guest'},
        {'mac':OTHER,'ip':'10.42.0.30','name':'Stale cached guest'}]}))
    original = LinuxEnforcer
    monkeypatch.setattr('securiot_agent.linux_enforcement.LinuxEnforcer',
                        lambda config, path, devices: original(config,path,devices,run=lab.machine))
    agent, collector = build(None,lab.path,linux_config=lab.config,model_mode='rules')
    try:
        assert set(agent.inventory.devices)=={MAC}
        assert agent.inventory.get(MAC).status=='blocked'
        assert agent.enforcer.restrictions=={MAC:'blocked'}
        result=agent.request_action('restore',MAC,manual=True)
        assert result.actions_taken==['restore']
        assert agent.enforcer.restrictions=={}
    finally:agent.enforcer.close()
