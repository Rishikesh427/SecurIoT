import { useState } from "react";
import { api } from "../api/client";
import { actionLabel, clock, isContained } from "../lib/format";
import type { ActionName, AuditEntry, Device } from "../types";
import { Modal } from "./Modal";
import { Button, SectionTitle, Tag } from "./ui";
const tones = { requested: "neutral", applied: "ok", failed: "bad", would_have: "warn" } as const;
const labels = { requested: "Requested", applied: "Applied — reported", failed: "Failed", would_have: "Would have" };

export function ActivityView({ devices, entries, onAction, canAct, canRunAudit }: {
  devices: Device[]; entries: AuditEntry[]; onAction: (action: ActionName, mac: string) => void; canAct: boolean; canRunAudit: boolean;
}) {
  const [summary, setSummary] = useState<string[] | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState(false);
  async function run() {
    if (running) return;
    setRunning(true); setError(null);
    try {
      const result = await api.runAudit();
      setSummary(result.bullets?.length === 3 ? result.bullets : [
        "An audit report is available. This server does not yet provide the simplified summary.",
        "Open the audit log to check reported actions and pending requests.",
        "Review suggested fixes before restoring a device; access changes do not repair it.",
      ]);
    }
    catch (e) { setError(e instanceof Error ? e.message : "Audit failed"); }
    finally { setRunning(false); }
  }
  return <section>
    <SectionTitle action={<div className="flex flex-wrap gap-2">
      <Button variant="primary" onClick={() => void run()} disabled={running || !canRunAudit}>{running ? "Running Audit…" : "Run Audit"}</Button>
      <Button onClick={() => setOpen(true)}>Open Audit Log</Button>
    </div>}>Security Digest</SectionTitle>
    {error && <p role="alert" className="mt-3 text-bad">{error}</p>}
    {summary && <ul aria-label="Audit Summary" className="mt-4 list-disc space-y-3 pl-6 leading-relaxed text-ink-2">{summary.map((bullet, index) => <li key={index}>{bullet}</li>)}</ul>}
    {open && <Modal title="Audit Log" onClose={() => setOpen(false)}>
      {!entries.length ? <p>No audit entries loaded.</p> : <ul className="divide-y divide-hairline">{entries.map((entry) => {
        const device = devices.find((d) => d.mac === entry.mac);
        const undo = canAct && ['quarantine', 'block_wan'].includes(entry.action) && entry.outcome === 'applied' && device && isContained(device.status);
        return <li key={entry.id} className="flex items-center justify-between gap-3 py-3">
          <div><p className="text-sm font-medium">{actionLabel[entry.action] ?? entry.action.replace(/_/g, ' ')} <Tag tone={tones[entry.outcome]}>{labels[entry.outcome]}</Tag></p>
            <p className="mt-1 text-xs text-ink-3">{device?.label ?? entry.mac ?? 'All devices'} · {entry.actor} · {clock(entry.ts)}</p></div>
          {undo && <Button onClick={() => onAction('restore', entry.mac!)}>Restore</Button>}
        </li>;
      })}</ul>}
    </Modal>}
  </section>;
}
