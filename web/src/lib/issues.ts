// Turns devices + events + policy into "things that need attention": each with
// a severity, a plain-language title, why it matters, steps, and a fix action.
import type { DashDevice, Policy, SecurEvent } from "../types";
import { isContained, shortLabel, toMs } from "./format";
import { cleanupSteps, isIncident } from "./incident";
import type { Severity } from "./severity";

export type FixAction = "turn_on_protection" | "isolate" | "protect_and_isolate" | "restore";

export interface Issue {
  id: string; // stable, so "mark as done" sticks
  severity: Severity;
  title: string;
  summary: string; // one plain sentence
  why: string;
  steps: string[];
  mac?: string;
  action?: { kind: FixAction; label: string };
  technical: string[]; // jargon lives here, shown only in details
}

const RECENT_MS = 10 * 60_000;

export function deriveIssues(
  devices: DashDevice[],
  events: SecurEvent[],
  policy: Policy | null,
  opts: { now: number; canAct: boolean },
): Issue[] {
  const issues: Issue[] = [];
  const name = (mac: string) => shortLabel(devices.find((d) => d.mac === mac)?.label ?? "A device");

  // 1. Devices that are cut off right now: contained, not fixed.
  for (const d of devices.filter((x) => isContained(x.status))) {
    const label = shortLabel(d.label);
    issues.push({
      id: `contained:${d.mac}:${events.find((e) => e.mac === d.mac && e.actions_taken.length)?.id ?? d.last_seen}`,
      severity: "critical",
      title: `${label} was cut off`,
      summary: `It started attacking your network, so SecurIoT isolated it. It's still infected until you clean it up.`,
      why: "Isolation stops the attack from spreading, but whatever infected the device is still on it.",
      steps: cleanupSteps(d),
      mac: d.mac,
      action: opts.canAct ? { kind: "restore", label: "Restore when clean" } : undefined,
      technical: [`status: ${d.status}`, `mac: ${d.mac}`, `ip: ${d.ip}`],
    });
  }

  // 2. Attacks detected but not stopped (learning mode), in the last 10 minutes.
  const seen = new Set<string>();
  for (const e of events.filter(isIncident)) {
    const d = devices.find((x) => x.mac === e.mac);
    if (!d || isContained(d.status) || seen.has(e.mac) || e.actions_taken.length) continue;
    if (opts.now - (toMs(e.ts) ?? 0) > RECENT_MS) continue;
    seen.add(e.mac);
    issues.push({
      id: `uncontained:${e.id}`,
      severity: "critical",
      title: `${name(e.mac)} is attacking your network`,
      summary: "It started probing other devices, which is typical of malware. Protection is off, so it wasn't stopped.",
      why: "An infected device can try to break into your other devices or spy on your network.",
      steps: ["Isolate it now to cut it off.", "Turn on automatic protection so this is handled for you next time.", ...cleanupSteps(d)],
      mac: e.mac,
      // The API refuses containment while protection is off, so turn it on first.
      action: !opts.canAct ? undefined : policy?.learning_mode ? { kind: "protect_and_isolate", label: "Turn on protection and isolate" } : { kind: "isolate", label: "Isolate now" },
      technical: [`event: ${e.kind}`, `would_have: ${e.would_have.join(", ")}`, `event id: ${e.id}`],
    });
  }

  // 3. Protection switched off.
  if (policy?.learning_mode) {
    issues.push({
      id: "learning_mode",
      severity: "high",
      title: "Automatic protection is off",
      summary: "SecurIoT is watching, but it won't stop an attack on its own.",
      why: "Attacks spread in seconds. With protection on, a misbehaving device is cut off before you'd notice.",
      steps: ["Turn on automatic protection.", "SecurIoT will isolate any device that starts attacking your network. You can undo it with Restore."],
      action: { kind: "turn_on_protection", label: "Turn on" },
      technical: ["policy.learning_mode: true"],
    });
  }

  // 4. Standing weaknesses on devices that are otherwise fine.
  for (const d of devices) {
    if (isContained(d.status) || d.protected) continue;
    const label = shortLabel(d.label);
    if (d.default_creds) {
      issues.push({
        id: `default_creds:${d.mac}`,
        severity: "high",
        title: `${label} uses its factory password`,
        summary: "Anyone who knows the default password can take it over.",
        why: "Factory passwords are published online. They're the first thing attackers try.",
        steps: ["Open the device's settings page or app.", "Change the admin password to something long and unique.", "Mark this as done."],
        mac: d.mac,
        technical: ["default_creds: true", ...d.reasons.filter((r) => /default/i.test(r))],
      });
    }
    if (d.eol) {
      issues.push({
        id: `eol:${d.mac}`,
        severity: "medium",
        title: `${label} no longer gets security updates`,
        summary: "The maker stopped fixing security problems in it.",
        why: "New weaknesses will never be patched, so the risk only grows over time.",
        steps: ["Keep it blocked from the internet if it still works without it.", "Plan to replace it with a model that's still supported."],
        mac: d.mac,
        technical: ["eol: true", ...d.reasons.filter((r) => /end.of.life|eol|kev/i.test(r))],
      });
    }
    if (d.ports.some((p) => p === 23 || p === 2323)) {
      issues.push({
        id: `telnet:${d.mac}`,
        severity: "medium",
        title: `${label} has an unprotected remote login`,
        summary: "It accepts remote logins over an old, unencrypted connection.",
        why: "This kind of login is a common way malware gets into cameras and routers.",
        steps: ["Turn off remote login (Telnet) in the device's settings, if it has the option.", "If it can't be turned off, keep the device isolated from your other devices."],
        mac: d.mac,
        technical: [`open ports: ${d.ports.join(", ")}`, "telnet on 23/2323"],
      });
    }
  }

  return issues.sort((a, b) => sevRank(a.severity) - sevRank(b.severity));
}

const sevRank = (s: Severity) => ({ critical: 0, high: 1, medium: 2, low: 3 })[s];
