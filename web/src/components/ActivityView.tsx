import { useState } from "react";
import { api, isMissing } from "../api/client";
import { usePoll } from "../hooks/usePoll";
import { actionLabel, clock, isContained } from "../lib/format";
import type { ActionName, AuditEntry, Device, SecurEvent } from "../types";
import { ActivityList } from "./ActivityList";
import { Button, Card, SectionTitle, Tag } from "./ui";

const UNDOABLE = new Set(["quarantine", "block_wan"]);
const outcomeTone = { requested: "neutral", applied: "ok", failed: "bad", would_have: "warn" } as const;
const outcomeLabel = { requested: "Requested", applied: "Applied", failed: "Failed", would_have: "Would have" };

export function ActivityView({
  devices,
  events,
  onAction,
  onSelect,
  canAct,
  canRunAudit,
}: {
  devices: Device[];
  events: SecurEvent[];
  onAction: (action: ActionName, mac: string) => void;
  onSelect: (mac: string) => void;
  canAct: boolean;
  canRunAudit: boolean;
}) {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [summary, setSummary] = useState<{ text: string; at: number } | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [hasAudit, setHasAudit] = useState(true);

  usePoll(
    async () => {
      try {
        setEntries(await api.audit());
      } catch (e) {
        if (isMissing(e)) setHasAudit(false);
        // other failures: the offline banner covers it
      }
    },
    2000,
    hasAudit,
  );

  async function run() {
    setRunning(true);
    setError(null);
    try {
      setSummary({ text: (await api.runAudit()).summary, at: Date.now() });
    } catch (e) {
      setError(e instanceof Error ? e.message : "Audit failed");
    } finally {
      setRunning(false);
    }
  }

  const name = (mac?: string) => (mac ? devices.find((d) => d.mac === mac)?.label ?? mac : "All devices");
  const [headline, ...rest] = summary?.text.split(/\n\s*\n/) ?? [];

  return (
    <div className="grid gap-10 lg:grid-cols-[1fr_1fr]">
      <div className="space-y-10">
        <div>
          <SectionTitle
            action={
              <Button variant="primary" onClick={run} disabled={running || !canRunAudit}>
                {running ? "Running" : "Run audit"}
              </Button>
            }
          >
            Security digest
          </SectionTitle>
          <Card className="px-6 py-5">
            {error && <p className="mb-3 text-[13px] text-bad">{error}</p>}
            {!summary ? (
              <p className="text-[14px] leading-relaxed text-ink-3">
                {canRunAudit ? "Run an audit for a plain-language summary of your network." : "The digest will be available once the server supports it."}
              </p>
            ) : (
              <div key={summary.at} className="animate-rise-in">
                <h3 className="text-[20px] font-semibold leading-snug tracking-tight text-ink">{headline}</h3>
                {rest.map((p) => (
                  <p key={p} className="mt-3 text-[15px] leading-relaxed text-ink-2">
                    {p}
                  </p>
                ))}
                <p className="mt-4 text-[12px] text-ink-3">Generated at {clock(new Date(summary.at).toISOString())}</p>
              </div>
            )}
          </Card>
        </div>

        <div>
          <SectionTitle>Audit log</SectionTitle>
          <Card className="overflow-hidden">
            {!hasAudit ? (
              <p className="px-5 py-8 text-center text-[14px] text-ink-3">The audit log will appear once the server supports it.</p>
            ) : entries.length === 0 ? (
              <p className="px-5 py-8 text-center text-[14px] text-ink-3">Every action taken by you or CasaWarden appears here.</p>
            ) : (
              <ul className="divide-y divide-hairline">
                {entries.map((e) => {
                  const d = devices.find((x) => x.mac === e.mac);
                  const canUndo = canAct && UNDOABLE.has(e.action) && e.outcome === "applied" && d && isContained(d.status);
                  return (
                    <li key={e.id} className="flex items-center gap-4 px-5 py-3.5">
                      <div className="min-w-0 flex-1">
                        <div className="flex items-baseline justify-between gap-3">
                          <span className="flex items-center gap-2 text-[14px] font-medium text-ink">
                            {actionLabel[e.action] ?? e.action.replace(/_/g, " ")}
                            <Tag tone={outcomeTone[e.outcome]}>{outcomeLabel[e.outcome]}</Tag>
                          </span>
                          <time className="shrink-0 text-[12px] tabular-nums text-ink-3">{clock(e.ts)}</time>
                        </div>
                        <div className="truncate text-[13px] text-ink-2">
                          {name(e.mac)}  ·  by {e.actor}
                        </div>
                      </div>
                      {canUndo && <Button onClick={() => onAction("restore", e.mac!)}>Undo</Button>}
                    </li>
                  );
                })}
              </ul>
            )}
          </Card>
        </div>
      </div>

      <div>
        <SectionTitle>All activity</SectionTitle>
        <ActivityList events={events} devices={devices} onSelect={onSelect} />
      </div>
    </div>
  );
}
