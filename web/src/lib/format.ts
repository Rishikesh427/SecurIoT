import type { Band, Confidence, DeviceStatus, EventKind } from "../types";

/** Contract timestamps are ISO strings; feed meta may also send epoch numbers. */
export function toMs(ts: string | number | null | undefined): number | null {
  if (ts == null) return null;
  if (typeof ts === "number") return ts < 1e12 ? ts * 1000 : ts;
  const ms = Date.parse(ts);
  return Number.isNaN(ms) ? null : ms;
}

export function bytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${units[i]}`;
}

export function clock(ts: string): string {
  return new Date(ts).toLocaleTimeString([], { hour: "numeric", minute: "2-digit", second: "2-digit" });
}

export function ago(ts: string, now = Date.now()): string {
  const s = Math.max(0, Math.round((now - (toMs(ts) ?? now)) / 1000));
  if (s < 5) return "Now";
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  return `${Math.round(m / 60)}h ago`;
}

export const bandColor: Record<Band, string> = {
  low: "var(--color-ok)",
  medium: "var(--color-warn)",
  high: "var(--color-bad)",
};

export const bandLabel: Record<Band, string> = { low: "Low risk", medium: "Medium risk", high: "High risk" };
export const confidenceLabel: Record<Confidence, string> = { low: "Low confidence", medium: "Medium confidence", high: "High confidence" };

export const statusStyle: Record<DeviceStatus, { label: string; dot: string; text: string }> = {
  normal: { label: "Online", dot: "bg-ok", text: "text-ink-2" },
  wan_blocked: { label: "Internet blocked", dot: "bg-warn", text: "text-warn" },
  quarantined: { label: "Isolated", dot: "bg-bad", text: "text-bad" },
  offline: { label: "Offline", dot: "bg-ink-3", text: "text-ink-3" },
};

export const isContained = (s: DeviceStatus) => s === "quarantined" || s === "wan_blocked";

export const eventMeta: Record<EventKind, { label: string; severity: "info" | "warn" | "bad" }> = {
  scan_arp: { label: "Network sweep detected", severity: "warn" },
  scan_targets: { label: "Port scan detected", severity: "warn" },
  decoy_touch: { label: "Decoy accessed", severity: "bad" },
  new_domain: { label: "New domain contacted", severity: "info" },
  new_device: { label: "Device joined", severity: "info" },
};

export const severityDot = { info: "bg-ink-3", warn: "bg-warn", bad: "bg-bad", ok: "bg-ok" };

export const actionLabel: Record<string, string> = {
  block_wan: "Block internet",
  quarantine: "Quarantine",
  restore: "Restore",
  restore_all: "Restore all",
  policy_update: "Settings changed",
};

const HIDDEN_EVIDENCE = new Set(["simulated", "first_evidence_at", "enforced_at", "learning_mode"]);

export function describeEvidence(ev: Record<string, unknown>): string {
  return Object.entries(ev)
    .filter(([k, v]) => !HIDDEN_EVIDENCE.has(k) && (typeof v === "string" || typeof v === "number"))
    .map(([k, v]) => `${k.replace(/_/g, " ")} ${v}`)
    .join("  ·  ");
}

/** "Telnet open (+15)" -> { text: "Telnet open", points: 15 } */
export function parseReason(r: string): { text: string; points: number | null } {
  const m = /\s*\(\+(\d+)\)\s*$/.exec(r);
  return m ? { text: r.slice(0, m.index), points: Number(m[1]) } : { text: r, points: null };
}

/** Display name without the "(simulated)" suffix. */
export const shortLabel = (label: string) => label.replace(/\s*\(simulated[^)]*\)\s*$/i, "");
