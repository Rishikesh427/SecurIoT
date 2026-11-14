// Plain-language wording for the summary layer. Technical terms (KEV, Telnet,
// ARP, event kinds) only appear in the details the user opens on click.
import type { SecurEvent } from "../types";
import { parseReason } from "./format";

const REASONS: [RegExp, string][] = [
  [/kev/i, "Has a weakness hackers are known to use"],
  [/end.of.life|eol/i, "No longer gets security updates"],
  [/telnet/i, "Has an old, unprotected remote login open"],
  [/default password|default cred/i, "Still uses its factory password"],
  [/probing|anomal/i, "Started acting like malware"],
  [/plain.http|http admin/i, "Its settings page isn't encrypted"],
  [/cloud.only/i, "Only works through the maker's cloud"],
];

/** "Possible KEV match (+15)" -> { plain: "Has a weakness…", technical: "Possible KEV match", points: 15 } */
export function plainReason(reason: string) {
  const { text, points } = parseReason(reason);
  const plain = REASONS.find(([re]) => re.test(text))?.[1] ?? text;
  return { plain, technical: text, points };
}

export function plainEvent(e: SecurEvent): string {
  switch (e.kind) {
    case "volume":
      return "Used more traffic than its calibrated baseline; review needed";
    case "scan_arp":
      return "Searched your network for other devices";
    case "scan_targets":
      return "Tried to connect to many devices";
    case "decoy_touch":
      return "Contacted a decoy service";
    case "new_domain":
      return "Contacted a website it hasn't used before";
    case "new_device":
      return "Was first recorded on your network";
  }
}

export function plainOutcome(e: SecurEvent): string | null {
  if (e.source === "simulator" || e.evidence.simulated === true || e.evidence.enforcement === "mock") {
    return "Simulation: no real containment is reported";
  }
  if (e.actions_taken.includes("restore") || e.actions_taken.includes("restore_all")) return "The agent reported a restore action at that time";
  if (e.actions_taken.includes("quarantine")) return "The agent reported quarantine at that time";
  if (e.actions_taken.includes("block_wan")) return "The agent reported an internet block; local access may remain";
  if (e.would_have.length) return "Containment was proposed; no action was reported as applied";
  return null;
}
