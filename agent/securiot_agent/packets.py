"""Offline Ethernet decoding with Scapy. This module never opens a live socket."""

from dataclasses import dataclass
import math
from pathlib import Path
from collections.abc import Iterator

from scapy.error import Scapy_Exception
from scapy.layers.dhcp import DHCP
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import (
    IPv6, IPv6ExtHdrDestOpt, IPv6ExtHdrFragment, IPv6ExtHdrHopByHop, IPv6ExtHdrRouting,
)
from scapy.layers.l2 import ARP, Dot1Q, Ether
from scapy.packet import Packet
from scapy.utils import PcapReader

from .identify import safe_text
from .models import normalize_mac


@dataclass(frozen=True)
class PacketRecord:
    timestamp: float
    source_mac: str
    destination_mac: str
    captured_bytes: int
    source_ip: str | None = None
    destination_ip: str | None = None
    syn_target: tuple[str, int] | None = None
    arp_request: bool = False
    dns_queries: tuple[str, ...] = ()
    dhcp_hostname: str | None = None        # guest-controlled; already reduced to safe text
    dhcp_vendor_class: str | None = None
    listening_port: int | None = None       # source port of this device's own SYN-ACK

    def __post_init__(self) -> None:
        object.__setattr__(self, "source_mac", normalize_mac(self.source_mac))
        object.__setattr__(self, "destination_mac", normalize_mac(self.destination_mac))
        if not math.isfinite(self.timestamp) or self.timestamp < 0:
            raise ValueError("Packet timestamp must be finite and nonnegative")
        if self.captured_bytes < 0:
            raise ValueError("Captured byte length cannot be negative")


@dataclass
class CaptureStats:
    frames_read: int = 0
    ethernet_frames: int = 0
    skipped_frames: int = 0


def decode_packet(packet: Packet) -> PacketRecord | None:
    """Decode the outer Ethernet frame; don't confuse quoted inner IP with it."""
    if not isinstance(packet, Ether):
        return None
    network = packet.payload
    while isinstance(network, Dot1Q):
        network = network.payload

    source_ip = destination_ip = None
    syn_target = None
    arp_request = False
    dns_queries: tuple[str, ...] = ()
    dhcp_hostname = dhcp_vendor_class = None
    listening_port = None
    if isinstance(network, ARP):
        source_ip, destination_ip = str(network.psrc), str(network.pdst)
        arp_request = int(network.op) == 1
    elif isinstance(network, (IP, IPv6)):
        source_ip, destination_ip = str(network.src), str(network.dst)
        transport = network.payload
        # Do not interpret non-initial IP fragments as transport headers.
        if isinstance(network, IP) and network.frag:
            transport = None
        extension_headers = (IPv6ExtHdrDestOpt, IPv6ExtHdrFragment,
                             IPv6ExtHdrHopByHop, IPv6ExtHdrRouting)
        for _ in range(8):
            if not isinstance(transport, extension_headers):
                break
            if isinstance(transport, IPv6ExtHdrFragment) and transport.offset:
                transport = None
                break
            transport = transport.payload
        if isinstance(transport, TCP):
            flags = int(transport.flags)
            if flags & 0x02 and not flags & 0x10:  # SYN, without ACK
                syn_target = (destination_ip, int(transport.dport))
            elif flags & 0x12 == 0x12 and not flags & 0x04:  # SYN+ACK: this device is listening here
                listening_port = int(transport.sport)
        elif isinstance(transport, UDP) and transport.dport == 53:
            dns = transport.payload
            if isinstance(dns, DNS) and dns.qr == 0:
                names = {
                    question.qname.decode("ascii", errors="replace").rstrip(".").lower()
                    for question in dns.qd if question.qname
                }
                dns_queries = tuple(sorted(names))
        elif isinstance(transport, UDP) and transport.dport == 67 and isinstance(network, IP):
            # DHCP client message: DISCOVER/REQUEST carry the hostname and vendor class that
            # identify phones and microcontrollers. The sender's IP is 0.0.0.0 at this point.
            dhcp = packet.getlayer(DHCP)
            options = {o[0]: o[1] for o in dhcp.options if isinstance(o, tuple) and len(o) >= 2} if dhcp else {}
            if options.get("message-type") in (1, 3, "discover", "request"):  # wire gives ints; built packets give names
                dhcp_hostname = safe_text(options.get("hostname")) or None
                dhcp_vendor_class = safe_text(options.get("vendor_class_id"), 60) or None
    return PacketRecord(
        timestamp=float(packet.time), source_mac=packet.src, destination_mac=packet.dst,
        captured_bytes=len(packet.original) if packet.original else len(packet),
        source_ip=source_ip, destination_ip=destination_ip,
        syn_target=syn_target, arp_request=arp_request, dns_queries=dns_queries,
        dhcp_hostname=dhcp_hostname, dhcp_vendor_class=dhcp_vendor_class, listening_port=listening_port,
    )


def read_capture(path: Path, stats: CaptureStats | None = None) -> Iterator[PacketRecord]:
    """Stream Ethernet PCAP/PCAPNG records in timestamp order.

    Other link-layer formats are counted as skipped, never assigned invented
    MACs. A capture with only unsupported frames is rejected explicitly.
    """
    stats = stats if stats is not None else CaptureStats()
    previous_timestamp = -1.0
    try:
        # Own the input handle even if Scapy rejects the file in its constructor.
        with path.open("rb") as capture_file, PcapReader(capture_file) as reader:
            for packet in reader:
                stats.frames_read += 1
                timestamp = float(packet.time)
                if not math.isfinite(timestamp) or timestamp < 0:
                    raise ValueError("Capture contains an invalid timestamp")
                if timestamp < previous_timestamp:
                    raise ValueError("Capture timestamps are out of order; replay requires chronological packets")
                previous_timestamp = timestamp
                record = decode_packet(packet)
                if record is None:
                    stats.skipped_frames += 1
                    continue
                stats.ethernet_frames += 1
                yield record
    except (Scapy_Exception, EOFError) as error:
        raise ValueError(f"Cannot read capture {path}: {error}") from error
    if stats.frames_read and not stats.ethernet_frames:
        raise ValueError("Capture contains no supported Ethernet frames; raw-IP/Wi-Fi captures need conversion")
