import { useEffect, type ReactNode } from "react";
import { bandLabel, bytes, clock, confidenceLabel, describeEvidence, eventMeta, isContained, parseReason, severityDot } from "../lib/format";
import { cleanupSteps, deviceSummary, isIncident, summarize } from "../lib/incident";
import type { ActionName, DashDevice, SecurEvent } from "../types";
import { Button, Card, RiskRing, Status, Tag } from "./ui";

const yesNo = (v: boolean | null) => (v == null ? "Unknown" : v ? "Yes" : "No");

export function DeviceDetail({
  device,
  events,
  onClose,
  onAction,
  busy,
}: {
  device: DashDevice;
  events: SecurEvent[];
  onClose: () => void;
  onAction: (action: ActionName, mac: string) => void;
  busy: boolean;
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const mine = events.filter((e) => e.mac === device.mac);
  const contained = isContained(device.status);
  const incident = mine.find(isIncident);
  // Once restored, "it's been isolated" is no longer true; fall back to the risk summary.
  const summary = incident && (contained || !incident.actions_taken.length) ? summarize(incident, device) : deviceSummary(device);
  const steps = cleanupSteps(device);
  const reasons = device.reasons.map(parseReason);

  return (
    <div className="fixed inset-0 z-40 flex justify-end">
      <div className="absolute inset-0 animate-fade-in bg-black/20 backdrop-blur-[2px]" onClick={onClose} />
      <aside className="relative flex h-full w-full max-w-[520px] animate-sheet-in flex-col overflow-y-auto bg-[#fbfbfd] shadow-[-20px_0_60px_rgba(0,0,0,0.08)]">
        <header className="sticky top-0 z-10 flex items-center justify-between border-b border-hairline bg-[#fbfbfd]/80 px-6 py-3 backdrop-blur-xl">
          <span className="text-[13px] font-medium text-ink-2">Device</span>
          <Button variant="plain" className="h-8 px-2 text-[15px] font-semibold text-ink" onClick={onClose}>
            Done
          </Button>
        </header>

        <div className="space-y-6 px-6 pb-10 pt-6">
          <div className="flex items-center gap-5">
            <RiskRing risk={device.risk} band={device.band} size={76} />
            <div className="min-w-0">
              <h2 className="text-[24px] font-semibold leading-tight tracking-tight text-ink">{device.label}</h2>
              <p className="mt-1 text-[14px] text-ink-2">
                {[device.vendor, device.model].filter(Boolean).join(" ") || "Unknown vendor"}  ·  {device.ip}
              </p>
              <div className="mt-2 flex flex-wrap items-center gap-2">
                <Status status={device.status} />
                <Tag tone={device.band === "high" ? "bad" : device.band === "medium" ? "warn" : "ok"}>{bandLabel[device.band]}</Tag>
                {device.simulated && <Tag>Simulated</Tag>}
                {device.protected && <Tag>Protected</Tag>}
              </div>
            </div>
          </div>

          {contained ? (
            <Button variant="primary" className="w-full" disabled={busy} onClick={() => onAction("restore", device.mac)}>
              Restore
            </Button>
          ) : (
            <Button
              variant="destructive"
              className="w-full"
              disabled={busy || device.protected || device.status === "offline"}
              onClick={() => onAction("quarantine", device.mac)}
            >
              {device.protected ? "Protected devices can't be isolated" : "Isolate"}
            </Button>
          )}

          {contained && (
            <div className="rounded-2xl bg-warn/[0.08] px-4 py-3 text-[14px] leading-relaxed text-ink">
              <span className="font-semibold">Contained, not fixed.</span> The device is isolated, but it stays infected until you follow the steps
              below.
            </div>
          )}

          <Section title="Summary">
            <Card className="px-5 py-4">
              <p className="text-[15px] leading-relaxed text-ink">{summary.body}</p>
              <p className="mt-3 text-[14px] leading-relaxed text-ink-2">{summary.next}</p>
            </Card>
          </Section>

          <Section title="Risk breakdown" aside={confidenceLabel[device.confidence]}>
            <Card className="divide-y divide-hairline">
              {reasons.length === 0 ? (
                <p className="px-5 py-4 text-[14px] text-ink-3">No risk factors.</p>
              ) : (
                <>
                  {reasons.map((r) => (
                    <div key={r.text} className="px-5 py-3">
                      <div className="flex items-baseline justify-between gap-4">
                        <span className="text-[14px] text-ink">{r.text}</span>
                        {r.points != null && <span className="text-[14px] font-semibold tabular-nums text-ink">+{r.points}</span>}
                      </div>
                      {r.points != null && (
                        <div className="mt-2 h-1 overflow-hidden rounded-full bg-fill">
                          <div
                            className={`h-full rounded-full ${/probing|anomal/i.test(r.text) ? "bg-bad" : "bg-ink"}`}
                            style={{ width: `${(r.points / 40) * 100}%`, transition: "width 600ms var(--ease-apple)" }}
                          />
                        </div>
                      )}
                    </div>
                  ))}
                  <div className="flex items-baseline justify-between px-5 py-3">
                    <span className="text-[14px] text-ink-2">Total, capped at 100</span>
                    <span className="text-[17px] font-semibold tabular-nums text-ink">{device.risk}</span>
                  </div>
                </>
              )}
            </Card>
            {device.simulated && device.type === "camera" && (
              <p className="mt-2 px-1 text-[12px] text-ink-3">Vendor, model, end-of-life and KEV come from the simulated camera persona.</p>
            )}
          </Section>

          {steps.length > 0 && (
            <Section title="What to do">
              <Card className="divide-y divide-hairline">
                {steps.map((s, i) => (
                  <div key={s} className="flex gap-4 px-5 py-3.5">
                    <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-fill text-[12px] font-semibold text-ink-2">{i + 1}</span>
                    <span className="text-[14px] leading-relaxed text-ink">{s}</span>
                  </div>
                ))}
              </Card>
            </Section>
          )}

          <Section title="Details">
            <Card className="divide-y divide-hairline">
              <Detail label="MAC address" value={device.mac} mono />
              <Detail label="Open ports" value={device.ports.length ? device.ports.join(", ") : "None"} />
              <Detail label="Data in / out" value={`${bytes(device.bytes_in)} / ${bytes(device.bytes_out)}`} />
              <Detail label="End-of-life" value={yesNo(device.eol)} />
              <Detail label="Default password" value={yesNo(device.default_creds)} />
              {device.kev && <Detail label="Known exploited (KEV)" value={device.kev[0].toUpperCase() + device.kev.slice(1)} />}
              <Detail label="Talks to" value={device.dests.length ? device.dests.join(", ") : "Nothing"} />
            </Card>
          </Section>

          <Section title="Recent activity">
            <Card className="divide-y divide-hairline">
              {mine.length === 0 ? (
                <p className="px-5 py-4 text-[14px] text-ink-3">None.</p>
              ) : (
                mine.slice(0, 10).map((e) => {
                  const m = eventMeta[e.kind];
                  return (
                    <div key={e.id} className="flex items-start gap-3 px-5 py-3">
                      <span className={`mt-[7px] h-1.5 w-1.5 shrink-0 rounded-full ${severityDot[m?.severity ?? "info"]}`} />
                      <div className="min-w-0 flex-1">
                        <div className="flex justify-between gap-3 text-[14px]">
                          <span className="text-ink">{m?.label ?? e.kind}</span>
                          <time className="text-[12px] tabular-nums text-ink-3">{clock(e.ts)}</time>
                        </div>
                        <div className="truncate text-[12px] text-ink-2">{describeEvidence(e.evidence)}</div>
                      </div>
                    </div>
                  );
                })
              )}
            </Card>
          </Section>
        </div>
      </aside>
    </div>
  );
}

function Section({ title, aside, children }: { title: string; aside?: string; children: ReactNode }) {
  return (
    <section>
      <div className="mb-2 flex items-baseline justify-between px-1">
        <h3 className="text-[13px] font-semibold uppercase tracking-wide text-ink-3">{title}</h3>
        {aside && <span className="text-[12px] text-ink-3">{aside}</span>}
      </div>
      {children}
    </section>
  );
}

function Detail({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-baseline justify-between gap-6 px-5 py-3 text-[14px]">
      <span className="shrink-0 text-ink-2">{label}</span>
      <span className={`truncate text-right text-ink ${mono ? "font-mono text-[13px]" : ""}`}>{value}</span>
    </div>
  );
}
