"""Connect inventory → detector → safety policy → mock action → durable event."""

from collections.abc import Callable
import os
import time
import json
from typing import Any

from .detection import Detector
from .enforcement import Enforcer
from .inventory import Inventory
from .models import Event, Finding, Observation, normalize_mac
from .policy import Policy
from .storage import Storage


class Agent:
    def __init__(
        self,
        inventory: Inventory,
        detector: Detector,
        enforcer: Enforcer,
        storage: Storage,
        policy: Policy | None = None,
        clock: Callable[[], float] = time.time,
    ):
        if enforcer.simulated:
            if any(not d.simulated for d in inventory.devices.values()):
                raise ValueError("This build supports simulated devices and enforcement only.")
        else:
            if os.environ.get("SECURIOT_REAL_ENFORCEMENT") != "yes":
                raise ValueError("Real enforcement needs SECURIOT_REAL_ENFORCEMENT=yes")
            if any(d.simulated for d in inventory.devices.values()):
                raise ValueError('Real enforcement needs every device to have "simulated": false')
        if storage.mode != ("simulation" if enforcer.simulated else "linux"):
            raise ValueError("Use a separate Linux state directory for real enforcement")
        self.manual_protected = set(getattr(enforcer, 'protected', set())) | {
            d.mac for d in inventory.devices.values() if d.protected and not d.risk_facts.get('_demo_discovered')}
        self.inventory = inventory
        self.detector = detector
        self.enforcer = enforcer
        self.storage = storage
        self.policy = policy or Policy()
        self.policy.learning_mode = True  # Every start requires an explicit Arm.
        self.clock = clock
        self.ladder = {"notify": True, "block_wan": True, "quarantine": True}
        self.started_at = clock()
        # One detection event per device per (kind, decision) per window. A sustained
        # scan produces an observation per packet; without this a single sweep wrote
        # hundreds of identical "detection" events, flooding the audit log and pushing
        # every other device out of the dashboard's recent-events view.
        self._last_detection: dict[str, tuple[tuple[str, str], float]] = {}
        self.last_action_at: dict[str, float] = {}
        self.grace_until: dict[str, float] = {}
        self._load_saved_state()
        self.routine = None
        self._routine_second = None
        if hasattr(detector, "anomaly") and hasattr(detector, "assess_device"):
            from .routine import Routine
            self.routine = Routine(storage.directory, storage.mode, clock())
            self.detector.anomaly = self.routine.scores(clock())

    def _load_saved_state(self) -> None:
        state = self.storage.load_state()
        if not self.enforcer.simulated:
            self.enforcer.reconcile()
            for mac, record in state["devices"].items():
                self.last_action_at[mac] = record["last_action_at"]
                self.grace_until[mac] = record["grace_until"]
            # The backend journal is authoritative after a crash or local panic.
            for device in self.inventory.devices.values():
                device.status = "normal"
            for mac, status in self.enforcer.restrictions.items():
                device = self.inventory.get(mac)
                if device is not None:
                    device.status = status
                    device.last_seen = self.clock()
                    self._event("state_reapplied", mac, {"reason": "Linux restriction reconciled"})
            return
        for mac, record in state["devices"].items():
            device = self.inventory.get(mac)
            if device is None:
                self._event("state_skipped", mac, {"reason": "Device is no longer known"})
                continue
            self.last_action_at[mac] = record["last_action_at"]
            self.grace_until[mac] = record["grace_until"]
            status = record["status"]
            if status == "normal":
                continue
            if device.protected and not device.risk_facts.get('_demo_discovered'):
                self._event("state_skipped", mac, {"reason": "Device is now protected"})
                continue
            action = "block_wan" if status == "blocked" else "quarantine"
            # Restore the mock backend as well as the inventory after a restart.
            self.enforcer.apply(action, mac)
            device.status = status
            self._event("state_reapplied", mac, {"reason": "Saved simulated restriction"}, [action])

    def _save(self) -> None:
        self.storage.save_state({
            "version": 1,
            "mode": self.storage.mode,
            "saved_at": self.clock(),
            "devices": {
                mac: {
                    "status": device.status,
                    "last_action_at": self.last_action_at.get(mac, 0),
                    "grace_until": self.grace_until.get(mac, 0),
                }
                for mac, device in self.inventory.devices.items()
            },
        })

    def _event(
        self, kind: str, mac: str | None, evidence: dict[str, Any],
        actions_taken: list[str] | None = None, would_have: list[str] | None = None,
    ) -> Event:
        event = Event.at(
            self.clock(), kind=kind, mac=mac, evidence=evidence, simulated=self.enforcer.simulated,
            actions_taken=actions_taken or [], would_have=would_have or [],
        )
        self.storage.append_event(event)
        return event

    def set_armed(self, armed: bool) -> Event:
        self.policy.learning_mode = not armed
        return self._event("mode_changed", None, {
            "learning_mode": self.policy.learning_mode,
            "reason": "Explicit local Arm" if armed else "Learning mode enabled",
        })

    def _routine_assessment(self, device, assessment):
        if self.routine is None:
            return assessment
        baseline = self.routine.state["baselines"].get(device.mac)
        samples = self.routine.state["calibrating"].get(device.mac)
        status = (f"Volume baseline: frozen ({baseline['samples']} clean 10-second windows)." if baseline
                  else f"Volume baseline: calibrating ({len(samples)}/30 clean windows); learning mode required." if samples is not None
                  else "Volume baseline: not calibrated; volume detection unavailable.")
        assessment["reasons"] = [*assessment["reasons"], status]
        return assessment

    def routine_tick(self):
        routine = self.routine
        if routine is None:
            return
        now = self.clock()
        if int(now) == self._routine_second:
            return
        self._routine_second = int(now)
        for mac, score, evidence in routine.advance(now, self.inventory.devices, self.policy.learning_mode and now - self.started_at >= self.policy.warmup_seconds + 10):
            routine.signal(mac, score, now)
            self._event("detection", mac, {"finding": "volume", "detection": evidence,
                        "decision": "supporting_evidence_only"})
        self.detector.anomaly = routine.scores(now)
        for device in self.inventory.devices.values():
            assessment = self.detector.assess_device(device)
            assessment = self._routine_assessment(device, assessment)
            if assessment != device.assessment:
                device.assessment = assessment
                device.snapshot_at = now
        routine.save(now)

    def observe(self, observation: Observation) -> Event | None:
        self.routine_tick()
        if self.inventory.observe(observation, self.clock()) is None:
            return self._event("observation_ignored", observation.mac, {"reason": "Unknown device"})
        if self.routine is not None:
            device = self.inventory.get(observation.mac)
            eligible = (self.policy.learning_mode and device.status == "normal"
                and self.clock() - self.started_at >= self.policy.warmup_seconds
                and self.clock() >= self.grace_until.get(observation.mac, 0))
            self.routine.record(observation, self.clock(), eligible)
        finding = self.detector.observe(observation)
        if finding is not None:
            if not isinstance(finding, Finding) or type(finding.containment_allowed) is not bool or not isinstance(finding.evidence, dict):
                raise ValueError("Detector must return a Finding with a boolean containment decision and dictionary evidence")
            json.dumps(finding.evidence, allow_nan=False)
        if finding is not None and self.routine is not None:
            self.routine.flag(observation.mac)
            score = finding.evidence.get("ml_score", finding.evidence.get("anomaly", 0))
            self.routine.signal(observation.mac, score, self.clock())
            self.detector.anomaly = self.routine.scores(self.clock())
        assessor = getattr(self.detector, "assess_device", None)
        if assessor is not None:
            device = self.inventory.get(observation.mac)
            assessment = assessor(device)
            if (not isinstance(assessment, dict) or type(assessment.get("risk")) is not int
                    or not 0 <= assessment["risk"] <= 100
                    or assessment.get("band") != ("high" if assessment["risk"] >= 60 else "medium" if assessment["risk"] >= 30 else "low")
                    or assessment.get("confidence") not in {"confirmed", "possible", "likely", "n/a", "low", "medium", "high"}
                    or not isinstance(assessment.get("reasons"), list)
                    or any(not isinstance(reason, str) for reason in assessment["reasons"])):
                raise ValueError("Detector returned an invalid assessment; refusing to act")
            device.assessment = self._routine_assessment(device, assessment)
            device.snapshot_at = self.clock()
        if finding is None:
            return None
        if not finding.containment_allowed:
            return self._detection_event(observation.mac, finding.kind, "supporting_evidence_only", finding.evidence)
        action = self.choose_action(observation.mac, finding)
        if action is None:
            mac = normalize_mac(observation.mac)
            device = self.inventory.get(mac)
            if device is not None and device.protected:       # guards are reported even for notify-only
                decision = "protected_device"
            elif self.clock() < self.grace_until.get(mac, 0):
                decision = "restore_grace"
            elif self._score(finding) >= self.NOTIFY_AT:
                decision = "notify_only"
            else:
                decision = "below_notify_threshold"
            return self._detection_event(observation.mac, finding.kind, decision, finding.evidence)
        self._last_detection.pop(observation.mac, None)  # an action is a state change; log the next detection
        return self.request_action(action, observation.mac, finding=finding)

    NOTIFY_AT, BLOCK_AT, QUARANTINE_AT = 0.95, 0.97, 0.99   # detector score tiers
    DETECTION_REALERT_SECS = 10   # collapse repeated identical detections into one event per window

    def _detection_event(self, mac, kind, decision, evidence):
        """Emit a detection event, but collapse an unchanging situation (same finding
        and same decision) for one device to one event per window. A change of
        decision — e.g. normal -> restore_grace, or a new action — always emits."""
        key = (kind, decision)
        now = self.clock()
        last = self._last_detection.get(mac)
        if last is not None and last[0] == key and now - last[1] < self.DETECTION_REALERT_SECS:
            return None
        self._last_detection[mac] = (key, now)
        return self._event("detection", mac, {"finding": kind, "detection": evidence, "decision": decision})

    @staticmethod
    def _score(finding: Finding) -> float:
        # No numeric score: keep the old behaviour (contain). containment_allowed
        # has already filtered out findings that must never contain.
        return float(finding.evidence.get("anomaly", 0.99))

    def choose_action(self, mac: str, finding: Finding) -> str | None:
        """notify -> block_wan -> quarantine. A decoy touch, or a scan that continues
        after a WAN block, goes straight to quarantine. None means notify only."""
        score = self._score(finding)
        device = self.inventory.get(mac)
        # C's ARP rule reports a count-derived anomaly ratio, not a calibrated
        # model probability. Its containment eligibility was checked by the adapter.
        arp_rule = finding.kind == "scan_arp" and finding.evidence.get("detector") == "securiot_ml"
        if finding.kind == "decoy_touch" or arp_rule or score >= self.QUARANTINE_AT:
            wanted = "quarantine"
        elif device is not None and device.status == "blocked" and score >= self.BLOCK_AT:
            wanted = "quarantine"
        elif score >= self.BLOCK_AT:
            wanted = "block_wan"
        else:
            return None
        steps = ["quarantine", "block_wan"]
        for step in steps[steps.index(wanted):]:   # fall back to a step the policy still allows
            if self.ladder[step]:
                return step
        return None

    def request_action(self, action: str, mac: str | None = None, *, finding: Finding | None = None, manual: bool = False) -> Event:
        evidence: dict[str, Any] = {"requested_action": action, "manual": manual}
        if finding is not None:
            evidence.update({"finding": finding.kind, "detection": finding.evidence})
            device_for_evidence = self.inventory.get(mac) if mac else None
            if device_for_evidence:
                evidence["vulnerability_flags"] = device_for_evidence.assessment.get("vulnerability_flags", [])
        kind = "detection" if finding else "action"

        def decision(reason: str, *, taken: bool = False, learning: bool = False) -> Event:
            return self._event(kind, mac, {**evidence, "decision": reason},
                               [action] if taken else [], [action] if learning else [])

        if action not in {"block_wan", "quarantine", "power_cycle", "restore", "restore_all"}:
            return decision("rejected_unknown_action")
        if action == "power_cycle":
            return decision("rejected_unavailable_in_this_build")
        if action == "restore_all":
            return self._restore_all()
        try:
            mac = normalize_mac(mac or "")
        except ValueError:
            return decision("rejected_invalid_mac")
        device = self.inventory.get(mac)
        if device is None:
            return decision("rejected_unknown_device")

        now = self.clock()
        if action in ("block_wan", "quarantine") and not self.ladder[action]:
            return decision("disabled_by_policy")
        if action != "restore":
            if device.protected and (not manual or not device.risk_facts.get('_demo_discovered') or mac in self.manual_protected):
                return decision("protected_device")
            if not manual and now - self.started_at < self.policy.warmup_seconds:
                return decision("startup_warmup")
            if not manual and now < self.grace_until.get(mac, 0):
                return decision("restore_grace")
            if self.policy.learning_mode and not manual:
                return decision("learning_mode", learning=True)
            if not manual and mac in self.last_action_at and now - self.last_action_at[mac] < self.policy.cooldown_seconds:
                return decision("action_cooldown")
            if device.status == "quarantined" or (action == "block_wan" and device.status == "blocked"):
                return decision("already_restricted")
        try:
            self.enforcer.apply(action, mac)
        except Exception as error:
            # Preserve the last confirmed status; partial effects are not success.
            if not self.enforcer.simulated:
                evidence["enforcement_uncertain"] = True
                evidence["enforcement_error"] = str(error)
                evidence["recovery"] = "Intent retained; retry Restore or use local panic after stopping the agent"
            return decision(f"enforcement_failed: {type(error).__name__}")
        device.status = {"block_wan": "blocked", "quarantine": "quarantined", "restore": "normal"}[action]
        self.last_action_at[mac] = now
        device.last_seen = max(now, (device.last_seen or 0) + 0.000001)  # A newer snapshot must carry status changes even within one clock tick.
        if action == "restore":
            self.grace_until[mac] = now + self.policy.restore_grace_seconds
        self._save()
        return decision("applied_to_simulated_device" if self.enforcer.simulated else "applied_to_device", taken=True)

    def _restore_all(self) -> Event:
        restored: list[str] = []
        failed: list[str] = []
        pending = getattr(self.enforcer, "pending_macs", set())
        for mac, device in self.inventory.devices.items():
            if device.status == "normal" and mac not in pending:
                continue
            event = self.request_action("restore", mac)
            (restored if event.actions_taken else failed).append(mac)
        return self._event("action", None, {
            "requested_action": "restore_all", "restored_macs": restored,
            "failed_macs": failed, "decision": "partial_failure" if failed else "completed",
        }, [] if failed else ["restore_all"])
