"""Packet-derived deltas and rolling 10-second features, grouped by known MAC."""

from collections import deque
from dataclasses import dataclass
from collections.abc import Iterable

from .models import Observation, normalize_mac
from .packets import PacketRecord


@dataclass(frozen=True)
class _Activity:
    timestamp: float
    bytes_in: int
    bytes_out: int
    destination: str | None
    syn_target: tuple[str, int] | None
    arp_request: bool
    dns_queries: tuple[str, ...]


class TrafficCollector:
    """The same consume() boundary can later receive packets from a live sniffer.

    Known-device configuration is separate from untrusted traffic. Seeing a MAC
    here never makes it eligible for actions. This is not device discovery yet.
    """

    window_seconds = 10

    def __init__(self, known_macs: Iterable[str], *, max_window_packets: int = 100_000):
        self.windows: dict[str, deque[_Activity]] = {normalize_mac(mac): deque() for mac in known_macs}
        self.max_window_packets = max_window_packets
        self.latest_timestamp = -1.0
        self.matched_frames = 0
        self.unmatched_frames = 0

    def consume(self, packet: PacketRecord) -> list[Observation]:
        if packet.timestamp < self.latest_timestamp:
            raise ValueError("Collector requires chronological packets")
        self.latest_timestamp = packet.timestamp
        affected = {packet.source_mac, packet.destination_mac} & self.windows.keys()
        if not affected:
            self.unmatched_frames += 1
            return []
        self.matched_frames += 1
        observations = []
        for mac in sorted(affected):
            outgoing = mac == packet.source_mac
            incoming = mac == packet.destination_mac
            activity = _Activity(
                timestamp=packet.timestamp,
                bytes_in=packet.captured_bytes if incoming else 0,
                bytes_out=packet.captured_bytes if outgoing else 0,
                destination=packet.destination_ip if outgoing else None,
                syn_target=packet.syn_target if outgoing else None,
                arp_request=packet.arp_request if outgoing else False,
                dns_queries=packet.dns_queries if outgoing else (),
            )
            window = self.windows[mac]
            self._prune(window, packet.timestamp)
            if len(window) >= self.max_window_packets:
                raise ValueError(f"Too many packets in the window for {mac}; stopped rather than undercounting")
            window.append(activity)
            observations.append(self._snapshot(mac, activity, packet.timestamp))
        return observations

    def _prune(self, window: deque[_Activity], now: float) -> None:
        while window and window[0].timestamp < now - self.window_seconds:
            window.popleft()

    def _snapshot(self, mac: str, activity: _Activity, now: float) -> Observation:
        window = self.windows[mac]
        return Observation(
            mac=mac, bytes_in=activity.bytes_in, bytes_out=activity.bytes_out,
            packet_arp_requests=int(activity.arp_request),
            packet_syn_targets=(activity.syn_target,) if activity.syn_target is not None else (),
            destinations=tuple(sorted({a.destination for a in window if a.destination is not None})),
            syn_targets=tuple(sorted({a.syn_target for a in window if a.syn_target is not None})),
            arp_requests=sum(a.arp_request for a in window),
            dns_queries=tuple(sorted({name for a in window for name in a.dns_queries})),
            window_bytes_in=sum(a.bytes_in for a in window),
            window_bytes_out=sum(a.bytes_out for a in window), captured_at=now,
        )
