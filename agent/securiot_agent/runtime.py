"""Connect inventory → detector → safety policy → mock action → durable event."""

from collections.abc import Callable
import time
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
        if not enforcer.simulated or any(not d.simulated for d in inventory.devices.values()):
            raise ValueError("This build supports simulated devices and enforcement only.")
        self.inventory = inventory
        self.detector = detector
        self.enforcer = enforcer
        self.storage = storage
        self.policy = policy or Policy()
        self.policy.learning_mode = True  # Every start requires an explicit Arm.
        self.clock = clock
        self.started_at = clock()
        self.last_action_at: dict[str, float] = {}
        self.grace_until: dict[str, float] = {}
        self._load_saved_state()

    def _load_saved_state(self) -> None:
        state = self.storage.load_state()
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
            if device.protected:
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
            "mode": "simulation",
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
            self.clock(), kind=kind, mac=mac, evidence=evidence,
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

    def observe(self, observation: Observation) -> Event | None:
        if self.inventory.observe(observation, self.clock()) is None:
            return self._event("observation_ignored", observation.mac, {"reason": "Unknown device"})
        finding = self.detector.observe(observation)
        assessor = getattr(self.detector, "assess_device", None)
        if assessor is not None:
            device = self.inventory.get(observation.mac)
            device.assessment = assessor(device)
        if finding is None:
            return None
        if not finding.containment_allowed:
            return self._event("detection", observation.mac, {
                "finding": finding.kind, "detection": finding.evidence,
                "decision": "supporting_evidence_only",
            })
        return self.request_action("quarantine", observation.mac, finding=finding)

    def request_action(self, action: str, mac: str | None = None, *, finding: Finding | None = None) -> Event:
        evidence: dict[str, Any] = {"requested_action": action}
        if finding is not None:
            evidence.update({"finding": finding.kind, "detection": finding.evidence})
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
        if action != "restore":
            if device.protected:
                return decision("protected_device")
            if now - self.started_at < self.policy.warmup_seconds:
                return decision("startup_warmup")
            if now < self.grace_until.get(mac, 0):
                return decision("restore_grace")
            if self.policy.learning_mode:
                return decision("learning_mode", learning=True)
            if mac in self.last_action_at and now - self.last_action_at[mac] < self.policy.cooldown_seconds:
                return decision("action_cooldown")
            if device.status == "quarantined" or (action == "block_wan" and device.status == "blocked"):
                return decision("already_restricted")
        try:
            self.enforcer.apply(action, mac)
        except Exception as error:
            # Never claim containment when the backend failed.
            return decision(f"enforcement_failed: {type(error).__name__}")
        device.status = {"block_wan": "blocked", "quarantine": "quarantined", "restore": "normal"}[action]
        self.last_action_at[mac] = now
        if action == "restore":
            self.grace_until[mac] = now + self.policy.restore_grace_seconds
        self._save()
        return decision("applied_to_simulated_device", taken=True)

    def _restore_all(self) -> Event:
        restored: list[str] = []
        failed: list[str] = []
        for mac, device in self.inventory.devices.items():
            if device.status == "normal":
                continue
            event = self.request_action("restore", mac)
            (restored if event.actions_taken else failed).append(mac)
        return self._event("action", None, {
            "requested_action": "restore_all", "restored_macs": restored,
            "failed_macs": failed, "decision": "partial_failure" if failed else "completed",
        }, [] if failed else ["restore_all"])
