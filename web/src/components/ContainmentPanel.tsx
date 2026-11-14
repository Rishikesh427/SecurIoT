import { shortLabel, toMs } from "../lib/format";
import { incidentTiming, isEvidence, isIncident } from "../lib/incident";
import type { Device, SecurEvent } from "../types";
import { Card } from "./ui";

/** First-evidence -> enforcement timer, plus a before/after view of the device. */
export function ContainmentPanel({ events, devices, now }: { events: SecurEvent[]; devices: Device[]; now: number }) {
  const lastIncident = events.find(isIncident);
  const timing = lastIncident ? incidentTiming(lastIncident, events) : null;
  // Evidence after this point belongs to a new attack. In learning mode nothing is
  // enforced, so treat the rest of that burst (15 s) as part of the same incident.
  const settledAt = timing ? (timing.enforced ?? toMs(lastIncident!.ts)! + 15_000) : 0;
  const pending = events.filter((e) => isEvidence(e) && !isIncident(e) && toMs(e.ts)! > settledAt);
  const firstPending = pending.length ? toMs(pending[pending.length - 1].ts)! : null;
  const running = firstPending != null && now - firstPending < 15_000;

  let seconds: number | null = null;
  let label = "No incidents yet";
  if (running) {
    seconds = (now - firstPending!) / 1000;
    label = "Responding";
  } else if (timing?.enforced) {
    seconds = (timing.enforced - timing.first) / 1000;
    label = "From first evidence to isolation";
  } else if (lastIncident) {
    label = "Detected in learning mode, not isolated";
  }

  const focus = devices.find((d) => d.mac === lastIncident?.mac) ?? [...devices].sort((a, b) => b.risk - a.risk)[0];
  const quarantined = focus?.status === "quarantined";
  const blocked = focus?.status === "wan_blocked";
  const peers = devices.filter((d) => d.mac !== focus?.mac && d.status === "normal").length;

  const rows: [string, string, string][] = focus
    ? [
        ["Reachable devices", String(peers), quarantined ? "0" : String(peers)],
        ["Internet", "Allowed", quarantined || blocked ? "Blocked" : "Allowed"],
        ["Wi-Fi", "Connected", quarantined ? "Removed" : focus.status === "offline" ? "Offline" : "Connected"],
      ]
    : [];

  return (
    <Card>
      <div className="px-5 pb-4 pt-4">
        <div className="text-[13px] font-medium text-ink-2">Time to containment</div>
        <div className="mt-1 flex items-baseline gap-1">
          <span
            className={`text-[44px] font-semibold leading-none tracking-tight tabular-nums transition-colors ${
              running ? "text-warn" : seconds != null ? "text-ink" : "text-fill-2"
            }`}
          >
            {seconds != null ? seconds.toFixed(1) : "0.0"}
          </span>
          <span className="text-[17px] font-medium text-ink-3">sec</span>
        </div>
        <div className="mt-1.5 text-[13px] text-ink-3">{label}</div>
      </div>
      {focus && (
        <div className="border-t border-hairline px-5 py-3">
          <div className="grid grid-cols-[1fr_auto_auto] gap-x-6 gap-y-2 text-[13px]">
            <span className="text-ink-3">{shortLabel(focus.label)}</span>
            <span className="text-right text-ink-3">Before</span>
            <span className="text-right text-ink-3">Now</span>
            {rows.map(([k, before, after]) => (
              <div key={k} className="contents">
                <span className="text-ink-2">{k}</span>
                <span className="text-right text-ink-2">{before}</span>
                <span className={`text-right font-medium ${after !== before ? "text-ok" : "text-ink"}`}>{after}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </Card>
  );
}
