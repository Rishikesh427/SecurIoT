import { useState } from "react";
import { ChevronDown } from "lucide-react";
import { clock, eventMeta, severityDot, shortLabel } from "../lib/format";
import { plainEvent, plainOutcome } from "../lib/plain";
import type { Device, SecurEvent } from "../types";
import { Card } from "./ui";

/** Plain summary per event; the raw log entry opens on click. */
export function ActivityList({
  events,
  devices,
  onSelect,
  limit,
}: {
  events: SecurEvent[];
  devices: Device[];
  onSelect: (mac: string) => void;
  limit?: number;
}) {
  const [open, setOpen] = useState<string | null>(null);
  const name = (mac: string) => shortLabel(devices.find((d) => d.mac === mac)?.label ?? "Unknown device");
  const shown = limit ? events.slice(0, limit) : events;

  return (
    <Card className="overflow-hidden">
      {shown.length === 0 ? (
        <p className="px-5 py-8 text-center text-[14px] text-ink-3">No activity yet.</p>
      ) : (
        <ol className="divide-y divide-hairline">
          {shown.map((e) => {
            const m = eventMeta[e.kind] ?? { severity: "info" as const };
            const outcome = plainOutcome(e);
            const expanded = open === e.id;
            return (
              <li key={e.id} className="animate-fade-in">
                <button
                  onClick={() => setOpen(expanded ? null : e.id)}
                  aria-expanded={expanded}
                  className="flex w-full items-start gap-3.5 px-5 py-3.5 text-left transition-colors hover:bg-fill/70"
                >
                  <span className={`mt-[7px] h-2 w-2 shrink-0 rounded-full ${severityDot[m.severity]}`} />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-baseline justify-between gap-3">
                      <span className="text-[14px] text-ink">
                        <span className="font-medium">{name(e.mac)}</span> {plainEvent(e).toLowerCase()}
                      </span>
                      <time className="shrink-0 text-[12px] tabular-nums text-ink-3">{clock(e.ts)}</time>
                    </div>
                    {outcome && <div className={`mt-0.5 text-[13px] font-medium ${e.actions_taken.length ? "text-bad" : "text-warn"}`}>{outcome}</div>}
                  </div>
                  <ChevronDown size={16} className={`mt-1 shrink-0 text-ink-3 transition-transform duration-300 ${expanded ? "rotate-180" : ""}`} aria-hidden />
                </button>
                {expanded && (
                  <div className="animate-expand px-5 pb-4 pl-[42px]">
                    <pre className="overflow-x-auto rounded-xl bg-fill px-4 py-3 font-mono text-[11.5px] leading-relaxed text-ink-2">
                      {JSON.stringify({ kind: e.kind, ts: e.ts, mac: e.mac, evidence: e.evidence, actions_taken: e.actions_taken, would_have: e.would_have, source: e.source, id: e.id }, null, 2)}
                    </pre>
                    <button onClick={() => onSelect(e.mac)} className="mt-2 text-[13px] font-medium text-ink-2 hover:text-ink">
                      View device
                    </button>
                  </div>
                )}
              </li>
            );
          })}
        </ol>
      )}
    </Card>
  );
}
