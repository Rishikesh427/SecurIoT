"""Internal isolated Docker lab worker; never captures the host interface."""
import asyncio
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import time

assert os.environ.get("SECURIOT_DECOY_LAB") == "1", "This worker is only for the isolated test lab"
from scapy.sendrecv import AsyncSniffer
from securiot_agent.decoys import start_decoys
from securiot_agent.live import build, make_handler
from securiot_agent.simulation import DemoClock


async def main():
    ip = socket.gethostbyname(socket.gethostname())
    peer_ip, peer_mac = os.environ["PEER_IP"], os.environ["PEER_MAC"]
    with tempfile.TemporaryDirectory() as directory:
        devices = Path(directory) / "devices.json"
        devices.write_text(json.dumps({"devices":[{"mac":peer_mac,"ip":peer_ip,"name":"isolated lab client"}]}))
        clock = DemoClock(time.time()-31)
        agent, collector = build(devices,Path(directory)/"state",armed=True,decoy_ips=[ip],clock=clock,model_mode="rules")
        clock.now = time.time()  # Prime warmup only in this controlled test.
        events, connections = [], []
        ready = threading.Event()
        sniffer = AsyncSniffer(iface="eth0",prn=make_handler(agent,collector,events.append),store=False,started_callback=ready.set)
        servers = await start_decoys(ip,[2323],known_ips={peer_ip:peer_mac},on_hit=connections.append)
        sniffer.start()
        try:
            if not await asyncio.to_thread(ready.wait,5):
                raise RuntimeError("Raw sniffer did not start")
            print("READY",flush=True)
            deadline = time.monotonic()+15
            while time.monotonic() < deadline:
                if events and connections and agent.inventory.get(peer_mac).status == "quarantined":
                    assert events[0].evidence["finding"] == "decoy_touch"
                    assert events[0].mac == peer_mac
                    print(json.dumps({"live_interface":"eth0","actual_tcp_connection":True,
                        "packet_mac":events[0].mac,"listener_mapped_mac":connections[0]["mapped_mac"],
                        "finding":"decoy_touch","mock_status":"quarantined","warmup_primed_for_test":True}),flush=True)
                    return
                await asyncio.sleep(.05)
            raise AssertionError("Real packet/listener/detection chain did not complete")
        finally:
            sniffer.stop()
            for server in servers:
                server.close()
                await server.wait_closed()

asyncio.run(main())
