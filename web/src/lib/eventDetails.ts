import type { SecurEvent } from "../types";

export type EventOutcome =
  | "reported_applied"
  | "would_have"
  | "failed"
  | "no_action";

export const outcomeLabels: Record<EventOutcome, string> = {
  reported_applied: "Applied — reported",
  would_have: "Would have acted",
  failed: "Failed or uncertain",
  no_action: "Informational",
};

export const actionNames: Record<string, string> = {
  block_wan: "Block internet",
  quarantine: "Quarantine",
  restore: "Restore",
  restore_all: "Restore all",
};

export function decisionCode(event: SecurEvent): string | null {
  const value = event.evidence.decision;
  return typeof value === "string" ? value : null;
}

export function eventOutcome(event: SecurEvent): EventOutcome {
  const decision = decisionCode(event) ?? "";

  if (
    event.evidence.enforcement_uncertain === true ||
    decision.startsWith("enforcement_failed") ||
    decision === "partial_failure"
  ) {
    return "failed";
  }

  if (event.actions_taken.length) return "reported_applied";
  if (event.would_have.length) return "would_have";
  return "no_action";
}

const decisions: Record<string, string> = {
  supporting_evidence_only:
    "This finding was advisory. It was not eligible for automatic containment.",
  protected_device:
    "The device was protected, so the requested restriction was not applied.",
  startup_warmup:
    "Automatic containment was paused during startup warmup.",
  restore_grace:
    "Automatic containment was paused during the restore grace period.",
  learning_mode:
    "Learning mode recorded the proposed action without applying it.",
  action_cooldown:
    "The automatic-action cooldown prevented another action.",
  already_restricted:
    "The requested restriction was already in place.",
  disabled_by_policy:
    "The requested response was disabled by policy.",
  notify_only:
    "The finding was recorded without a containment action.",
  below_notify_threshold:
    "The finding did not reach the notification threshold.",
  applied_to_simulated_device:
    "The mock backend recorded the action. This is not physical containment.",
  applied_to_device:
    "The enforcement backend reported that the action was applied.",
};

export function decisionText(event: SecurEvent): string {
  const code = decisionCode(event);

  if (!code) return "No response decision was recorded for this event.";

  if (code.startsWith("enforcement_failed")) {
    return "Enforcement failed or could not be confirmed. Review before retrying.";
  }

  return decisions[code] ?? `Recorded decision: ${code}`;
}

export function isSimulated(event: SecurEvent): boolean {
  return (
    event.source === "simulator" ||
    event.evidence.simulated === true ||
    event.evidence.enforcement === "mock"
  );
}

export function outcomeSummary(event: SecurEvent): string {
  const simulated = isSimulated(event) ? " (simulated)" : "";
  const outcome = eventOutcome(event);

  if (outcome === "reported_applied") {
    const actions = event.actions_taken
      .map((a) => actionNames[a] ?? a)
      .join(", ");

    return `Reported actions: ${actions}${simulated}`;
  }

  return `${outcomeLabels[outcome]}${simulated}`;
}