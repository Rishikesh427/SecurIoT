// Derives incidents, containment timing and plain-language summaries from
// contract events. API templates remain visible while Gemini works or is unavailable.
import type { Device, SecurEvent } from "../types";
import { shortLabel, toMs } from "./format";
import { plainEvent, plainOutcome } from "./plain";

const EVIDENCE_KINDS = new Set(["scan_arp", "scan_targets", "decoy_touch"]);

/** An event that carried (or would have carried) an action bundle. */
export const isIncident = (e: SecurEvent) => e.actions_taken.length > 0 || e.would_have.length > 0;
export const isEvidence = (e: SecurEvent) => EVIDENCE_KINDS.has(e.kind);

/**
 * First evidence -> enforcement. Uses evidence.first_evidence_at / enforced_at
 * when the agent sends them; otherwise the earliest evidence for the same device
 * in the 15 s before the incident, and the incident's own timestamp.
 */
export function incidentTiming(incident: SecurEvent, events: SecurEvent[]) {
  const ts = toMs(incident.ts)!;
  const fromEvidence = (k: string) => (typeof incident.evidence[k] === "string" ? toMs(incident.evidence[k] as string) : null);
  const earliest = events
    .filter((e) => e.mac === incident.mac && isEvidence(e))
    .map((e) => toMs(e.ts)!)
    .filter((t) => t <= ts && ts - t <= 15_000)
    .reduce((a, b) => Math.min(a, b), ts);
  const first = fromEvidence("first_evidence_at") ?? earliest;
  const enforced = incident.actions_taken.length ? (fromEvidence("enforced_at") ?? ts) : null;
  return { first, enforced };
}

export interface Summary {
  headline: string;
  body: string;
  next: string;
  spoken: string;
  source: "gemini" | "pending" | "local";
}

/** Use the API's explanation in every state; only ready text is attributed to Gemini. */
function withGemini(e: SecurEvent, local: Omit<Summary, "source">): Summary {
  const source = e.explanation_status === "ready" ? "gemini" : e.explanation_status === "pending" ? "pending" : "local";
  if (e.explanation) {
    const { plain_language, recommended_next_step } = e.explanation;
    return { ...local, body: plain_language, next: recommended_next_step, spoken: plain_language, source };
  }
  return { ...local, source: e.explanation_status === "pending" ? "pending" : "local" };
}

export function summarize(incident: SecurEvent, device: Device | undefined): Summary {
  if (incident.kind === "volume") {
    return withGemini(incident, {
      headline: "Unusual traffic volume",
      body: "Traffic exceeded this device's calibrated baseline. This is advisory evidence, not proof of an attack.",
      next: "Review recent device activity and the baseline. No automatic containment was requested.",
      spoken: "Unusual traffic volume detected. Review recommended.",
    });
  }
  const name = device ? shortLabel(device.label).toLowerCase() : "a device";
  const simulated = incident.source === "simulator" || incident.evidence.simulated === true || incident.evidence.enforcement === "mock";
  const headline = simulated ? "Simulated observation" :
    incident.actions_taken.some(a => a === "restore" || a === "restore_all") ? "Restore reported" :
    incident.actions_taken.includes("quarantine") ? "Quarantine reported" :
    incident.actions_taken.includes("block_wan") ? "Internet block reported" : "Activity to review";
  const body = `Your ${name} ${plainEvent(incident).toLowerCase()}. ${plainOutcome(incident) ?? "No containment action was reported for this event"}.`;
  return withGemini(incident, { headline, body, spoken: body,
    next: "Review the recorded activity and verify the device's settings before changing its network access." });
}

export function deviceSummary(d: Device): { body: string; next: string } {
  const top = d.reasons.slice(0, 3).map((r) => r.replace(/\s*\(\+\d+\)\s*$/, "").toLowerCase());
  return {
    body: top.length ? `${shortLabel(d.label)} scores ${d.risk} out of 100: ${top.join(", ")}.` : `${shortLabel(d.label)} looks healthy. Nothing risky was found.`,
    next: d.band === "high" ? "Keep it off the internet if you can, and watch for unusual activity." : "No action needed.",
  };
}

export function cleanupSteps(d: Device): string[] {
  const steps: string[] = [];
  if (d.default_creds) steps.push("Change the default password.");
  if (d.eol) steps.push("It no longer gets updates. Keep it blocked from the internet or replace it.");
  if (d.ports.some((p) => p === 23 || p === 2323)) steps.push("Turn off Telnet in the device settings if possible.");
  if (d.ports.includes(80)) steps.push("Avoid using its plain-HTTP admin page on shared networks.");
  return steps;
}
