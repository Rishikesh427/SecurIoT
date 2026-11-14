"""Generate small, synthetic Ethernet captures. No traffic is transmitted.

Run from the repository root with the replay environment:
    agent/.venv/bin/python agent/tools/make_replay_fixtures.py
"""

import argparse
import json
from pathlib import Path

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.utils import PcapWriter

CAMERA = "02:00:00:00:00:20"
LAPTOP = "02:00:00:00:00:02"
ROUTER = "02:00:00:00:00:01"
BASE_TIME = 1_700_000_000


def timed(packet, seconds):
    packet.time = BASE_TIME + seconds
    return packet


def connection(seconds, host=50, port=80, *, source=CAMERA):
    return timed(
        Ether(src=source, dst=ROUTER)
        / IP(src="10.42.0.20" if source == CAMERA else "10.42.0.2", dst=f"10.42.0.{host}")
        / TCP(sport=40000, dport=port, flags="S"), seconds,
    )


def baseline():
    return [
        timed(Ether(src=CAMERA, dst="ff:ff:ff:ff:ff:ff")
              / ARP(op=1, hwsrc=CAMERA, psrc="10.42.0.20", pdst="10.42.0.1"), 0),
        timed(Ether(src=CAMERA, dst=ROUTER)
              / IP(src="10.42.0.20", dst="10.42.0.1") / UDP(sport=53000, dport=53)
              / DNS(rd=1, qd=DNSQR(qname="camera.example.test")), 1),
        connection(2),
        timed(Ether(src=ROUTER, dst=CAMERA)
              / IP(src="10.42.0.50", dst="10.42.0.20")
              / TCP(sport=80, dport=40000, flags="SA"), 2.1),
        connection(31),  # Keeps the trace beyond the 30-second safety warmup.
    ]


def write_capture(path, packets):
    with PcapWriter(str(path), linktype=1, sync=True) as writer:
        for packet in packets:
            writer.write(packet)


def generate(directory: Path):
    directory.mkdir(parents=True, exist_ok=True)
    write_capture(directory / "normal.pcap", baseline() + [connection(32 + i * 0.1) for i in range(25)])
    write_capture(directory / "scan.pcap", baseline() + [
        connection(32 + i * 0.1, host=50 + i) for i in range(20)
    ])
    write_capture(directory / "slow_targets.pcap", baseline() + [
        connection(32 + i, host=50 + i) for i in range(20)
    ])
    write_capture(directory / "protected_arp.pcap", baseline() + [
        timed(Ether(src=LAPTOP, dst="ff:ff:ff:ff:ff:ff")
              / ARP(op=1, hwsrc=LAPTOP, psrc="10.42.0.2", pdst=f"10.42.0.{50 + i}"),
              32 + i * 0.1) for i in range(30)
    ])
    (directory / "devices.json").write_text(json.dumps({"devices": [
        {"mac": CAMERA, "ip": "10.42.0.20", "name": "Camera (generated fixture)", "protected": False},
        {"mac": LAPTOP, "ip": "10.42.0.2", "name": "Dashboard laptop (generated fixture)", "protected": True},
    ]}, indent=2) + "\n")
    print(f"Wrote four synthetic PCAPs and known-device JSON to {directory}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path,
                        default=Path(__file__).resolve().parents[1] / "fixtures")
    generate(parser.parse_args().output_dir)
