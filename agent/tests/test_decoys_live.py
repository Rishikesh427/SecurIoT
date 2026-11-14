"""Actual TCP listener tests and the Scapy packet callback boundary."""
import asyncio
from pathlib import Path
import sys
import tempfile

import pytest
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT / "agent"))
from securiot_agent.decoys import start_decoys
from securiot_agent.live import build, make_handler
from securiot_agent.simulation import DemoClock


@pytest.mark.parametrize("mapped", [False, True])
def test_real_tcp_connection_logs_known_or_unknown_identity_and_closes(mapped):
    async def scenario():
        events = []
        servers = await start_decoys("127.0.0.1",[0],known_ips={"127.0.0.1":"02:00:00:00:00:20"} if mapped else {},on_hit=events.append)
        try:
            port = servers[0].sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection("127.0.0.1",port)
            assert await asyncio.wait_for(reader.read(),2) == b""
            writer.close()
            await writer.wait_closed()
            assert len(events) == 1
            assert events[0]["mapped_mac"] == ("02:00:00:00:00:20" if mapped else None)
            assert events[0]["mac_observed_in_packet"] is False
        finally:
            for server in servers:
                server.close()
                await server.wait_closed()
    asyncio.run(scenario())


@pytest.mark.parametrize("bind", ["0.0.0.0", "::", "224.0.0.1", "not-an-ip"])
def test_decoy_does_not_silently_bind_broadly(bind):
    with pytest.raises(ValueError):
        asyncio.run(start_decoys(bind,[8080]))


def test_live_callback_uses_observed_ethernet_mac_and_real_decoy_feature():
    with tempfile.TemporaryDirectory() as directory:
        clock = DemoClock(1000)
        agent, collector = build(ROOT / "agent/fixtures/devices.json",Path(directory),armed=True,
                                  decoy_ips=["10.42.0.51"],clock=clock,model_mode="required")
        clock.advance(31)
        packet = Ether(src="02:00:00:00:00:20",dst="02:00:00:00:00:01") / IP(
            src="10.42.0.20",dst="10.42.0.51") / TCP(dport=2323,flags="S")
        packet.time = 1031
        events = []
        make_handler(agent,collector,events.append)(packet)
        assert events[0].mac == "02:00:00:00:00:20"
        assert events[0].evidence["finding"] == "decoy_touch"
        assert agent.inventory.get(events[0].mac).status == "quarantined"
        assert agent.detector.model_status["active"]
