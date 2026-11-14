// Derives incidents, containment timing and plain-language summaries from
// contract events. There's no Gemini route in the contract yet, so summaries are
// the template fallback the plan calls for.
import type { Device, SecurEvent } from "../types";
import { shortLabel, toMs } from "./format";

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

/** Gemini's text once the API has it; our own plain wording until then. */
function withGemini(e: SecurEvent, local: Omit<Summary, "source">): Summary {
  if (e.explanation_status === "ready" && e.explanation) {
    const { plain_language, recommended_next_step } = e.explanation;
    return { ...local, body: plain_language, next: recommended_next_step, spoken: plain_language, source: "gemini" };
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
  const what = incident.kind === "decoy_touch" ? "probing other devices on your network, including a decoy" : "scanning other devices on your network";
  const contained = incident.actions_taken.length > 0;
  return withGemini(incident, contained
    ? {
        headline: "Threat contained",
        body: `Your ${name} started ${what}, which is typical of malware. It's been isolated from your network.`,
        next: "Unplug and replug it to clear it from memory, then change its default password before restoring it.",
        spoken: `Alert. Your ${name} started attacking other devices. SecurIoT has isolated it from your network.`,
      }
    : {
        headline: "Threat detected",
        body: `Your ${name} started ${what}, which is typical of malware. Learning mode is on, so SecurIoT only watched. With protection on, it would have been isolated.`,
        next: "Turn on automatic protection so threats like this are isolated right away.",
        spoken: `Warning. Your ${name} is attacking other devices. Learning mode is on, so it was not isolated.`,
      });
}

export function deviceSummary(d: Device): { body: string; next: string } {
  const top = d.reasons.slice(0, 3).map((r) => r.replace(/\s*\(\+\d+\)\s*$/, "").toLowerCase());
  return {
    body: top.length ? `${shortLabel(d.label)} scores ${d.risk} out of 100: ${top.join(", ")}.` : `${shortLabel(d.label)} looks healthy. Nothing risky was found.`,
    next: d.band === "high" ? "Keep it off the internet if you can, and watch for unusual activity." : "No action needed.",
  };
}

// Person C's old-camera cleanup wording, "isolated" throughout.
const CAMERA_STEPS = [
  "Unplug the camera and plug it back in. It's already isolated, so this safely clears malware that lives only in memory.",
  "Change the default password right after it restarts.",
  "Keep it blocked from the internet. It's end-of-life, so no fix is coming from the vendor.",
  "Consider replacing it with a model that still gets security updates.",
];

export function cleanupSteps(d: Device): string[] {
  if (d.type === "camera") return CAMERA_STEPS;
  const steps: string[] = [];
  if (d.default_creds) steps.push("Change the default password.");
  if (d.eol) steps.push("It no longer gets updates. Keep it blocked from the internet or replace it.");
  if (d.ports.some((p) => p === 23 || p === 2323)) steps.push("Turn off Telnet in the device settings if possible.");
  if (d.ports.includes(80)) steps.push("Avoid using its plain-HTTP admin page on shared networks.");
  return steps;
}
