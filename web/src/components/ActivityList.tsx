import { actionLabel, clock, describeEvidence, eventMeta, severityDot } from "../lib/format";
import type { Device, SecurEvent } from "../types";
import { Card } from "./ui";

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
  const name = (mac: string) => devices.find((d) => d.mac === mac)?.label ?? mac;
  const shown = limit ? events.slice(0, limit) : events;
  const list = (a: string[]) => a.map((x) => (actionLabel[x] ?? x).toLowerCase()).join(" and ");

  return (
    <Card className="overflow-hidden">
      {shown.length === 0 ? (
        <p className="px-5 py-8 text-center text-[14px] text-ink-3">No activity yet.</p>
      ) : (
        <ol className="divide-y divide-hairline">
          {shown.map((e) => {
            const m = eventMeta[e.kind] ?? { label: e.kind, severity: "info" as const };
            const outcome = e.actions_taken.length
              ? `Isolated: ${list(e.actions_taken)}`
              : e.would_have.length
                ? `Learning mode, would have: ${list(e.would_have)}`
                : null;
            const evidence = describeEvidence(e.evidence);
            return (
              <li key={e.id} className="animate-fade-in">
                <button onClick={() => onSelect(e.mac)} className="flex w-full items-start gap-3.5 px-5 py-3.5 text-left transition-colors hover:bg-fill/70">
                  <span className={`mt-[7px] h-2 w-2 shrink-0 rounded-full ${severityDot[m.severity]}`} />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-baseline justify-between gap-3">
                      <span className="text-[14px] font-medium text-ink">{m.label}</span>
                      <time className="shrink-0 text-[12px] tabular-nums text-ink-3">{clock(e.ts)}</time>
                    </div>
                    <div className="mt-0.5 truncate text-[13px] text-ink-2">
                      {name(e.mac)}
                      {evidence ? `  ·  ${evidence}` : ""}
                    </div>
                    {outcome && (
                      <div className={`mt-1 text-[13px] font-medium ${e.actions_taken.length ? "text-bad" : "text-warn"}`}>{outcome}</div>
                    )}
                  </div>
                </button>
              </li>
            );
          })}
        </ol>
      )}
    </Card>
  );
}
