"""A replaceable detector boundary and an explicitly demo-only implementation."""

from typing import Protocol

from .models import Finding, Observation


class Detector(Protocol):
    def observe(self, observation: Observation) -> Finding | None: ...


class DemoDetector:
    """Inspect synthetic window summaries, using the V3 example thresholds.

    This does not capture packets, maintain a rolling window, compute risk, or
    replace Worker C's securiot_ml. Its inputs already represent a 10 s window.
    """

    def observe(self, observation: Observation) -> Finding | None:
        targets = len(set(observation.syn_targets))
        if observation.arp_requests < 30 and targets < 20:
            return None
        return Finding(
            kind="scan",
            evidence={
                "detector": "demo_only",
                "window_seconds": 10,
                "arp_requests": observation.arp_requests,
                "unique_syn_targets": targets,
                "reason": "Synthetic activity meets a scan threshold; this is not proof of malware.",
            },
        )


class ReplayPreviewDetector:
    """Preview scan rules on packet-derived windows until Worker C integrates.

    Report crossings immediately and continuing activity at most once a second,
    so the agent can reconsider it after warmup or a policy change. It rearms
    when a metric drops below threshold. No risk scores or baselines are invented.
    """

    def __init__(self) -> None:
        self.active: dict[str, set[str]] = {}
        self.last_reported: dict[str, float] = {}

    def observe(self, observation: Observation) -> Finding | None:
        hits = set()
        if observation.arp_requests >= 30:
            hits.add("scan_arp")
        if len(set(observation.syn_targets)) >= 20:
            hits.add("scan_targets")
        previous = self.active.get(observation.mac, set())
        self.active[observation.mac] = hits
        new_hits = hits - previous
        captured_at = observation.captured_at
        continuing = bool(hits) and captured_at is not None and (
            captured_at - self.last_reported.get(observation.mac, captured_at) >= 1
        )
        if not new_hits and not continuing:
            return None
        if captured_at is not None:
            self.last_reported[observation.mac] = captured_at
        report_hits = new_hits or hits
        return Finding(
            kind="scan_targets" if "scan_targets" in report_hits else "scan_arp",
            evidence={
                "detector": "replay_threshold_preview",
                "input": "packet_capture",
                "captured_at": observation.captured_at,
                "window_seconds": 10,
                "arp_requests": observation.arp_requests,
                "unique_syn_targets": len(set(observation.syn_targets)),
                "window_bytes_in": observation.window_bytes_in,
                "window_bytes_out": observation.window_bytes_out,
                "dns_queries": list(observation.dns_queries),
                "reason": "Packet activity crossed a preview scan threshold; not proof of malware.",
            },
        )
