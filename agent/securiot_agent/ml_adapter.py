"""Translate packet deltas to Worker C's actual detector and scorer APIs."""

from collections.abc import Callable, Iterable
from typing import Any

from .vulnerabilities import VulnerabilityAssessor
from securiot_ml.detect import Detector as MLDetector

from .models import Device, Finding, Observation


class MLAdapter:
    def __init__(self, clock: Callable[[], float], protected_macs: Iterable[str] = ()):
        self.clock = clock
        self.detector = MLDetector()  # Protected devices remain visible; runtime prevents isolation.
        self.vulnerabilities = VulnerabilityAssessor()
        # C currently initializes t0 from wall time. Align its public startup
        # timestamp to the injected replay clock; retain its 30-second warmup.
        self.detector.t0 = clock()
        self.anomaly: dict[str, float] = {}

    def observe(self, observation: Observation) -> Finding | None:
        result = self.detector.observe(
            observation.mac, ts=self.clock(),
            arp=observation.packet_arp_requests,
            pairs=observation.packet_syn_targets,
            decoy_hits=observation.packet_decoy_hits,
            nbytes=observation.bytes_in + observation.bytes_out,
        )
        if result is None:
            return None
        anomaly = float(result.get("anomaly", 0))
        # Keep the strongest evidence seen during this offline session. Decay
        # and persistence of anomaly scores need a separately agreed policy.
        self.anomaly[observation.mac] = max(self.anomaly.get(observation.mac, 0), anomaly)
        evidence = {
            **result["evidence"], "detector": "securiot_ml", "input": "packet_capture",
            "captured_at": observation.captured_at, "anomaly": anomaly,
            "unique_syn_targets": result["evidence"].get("distinct_targets", 0),
            "arp_requests": result["evidence"].get("arp_in_window", 0),
        }
        # C explicitly marks scan_targets as supporting evidence. Other
        # supporting findings (including volume) cannot silently enable actions.
        eligible = result["kind"] in {"scan_arp", "decoy_touch"} and anomaly >= 0.5
        if result["kind"] == "scan_arp":
            evidence["distinct_arp_targets"] = len(observation.arp_targets)
            # Quantity alone can be repeated gateway-resolution failures.
            eligible = eligible and len(observation.arp_targets) >= 8
            if not eligible:
                evidence["containment_note"] = "ARP count alone lacks evidence of a multi-host sweep"
        return Finding(result["kind"], evidence, containment_allowed=eligible)

    def assess_device(self, device: Device) -> dict[str, Any]:
        return self.vulnerabilities.assess(device, self.anomaly.get(device.mac, 0))
