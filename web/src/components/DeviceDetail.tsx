import { useState, type ReactNode } from "react";
import { DeviceControls } from "../DeviceControls";
import { DeviceAdvisor } from "./Advisor";
import { ReadAloud } from "./ReadAloud";
import { titleCase } from "../lib/titles";
import { ChevronDown } from "lucide-react";
import { bandLabel, bytes, clock, eventMeta, isContained, severityDot } from "../lib/format";
import { plainEvent } from "../lib/plain";
import { cleanupSteps } from "../lib/incident";
import type { ActionName, DashDevice, Policy, SecurEvent } from "../types";
import { SidePanel } from "./SidePanel";
import { Button, Card, Status, Tag } from "./ui";

const yesNo = (v: boolean | null) => (v == null ? "Unknown" : v ? "Yes" : "No");

export function DeviceDetail({
  device,
  events,
  onClose,
  onAction,
  busy,
  canAct,
  policy,
  pending,
  onWarn,
  audioEnabled = true,
}: {
  device: DashDevice;
  events: SecurEvent[];
  onClose: () => void;
  onAction: (action: ActionName, mac: string) => void;
  busy: boolean;
  canAct: boolean;
  policy: Policy | null;
  pending?: string;
  onWarn?: (mac:string)=>void;
  audioEnabled?: boolean;
}) {
  const inferredVendor = typeof device.identification?.vendor === 'string' ? device.identification.vendor : null;
  const mine = events.filter((e) => e.mac === device.mac);
  const contained = isContained(device.status);
  const summary = contained ? (device.status === "wan_blocked" ? "Internet access is restricted. Review the fixes before restoring access." : "This device is quarantined. Review the fixes before restoring access.")
    : device.band === "high" ? "Reported risks need your attention. Review the score and next step."
    : device.band === "medium" ? "Review this device's reported risks and available fixes."
    : "Review the available device information and suggested fixes.";
  const steps = cleanupSteps(device);
  const [showTech, setShowTech] = useState(false);
  const [visibleEvents,setVisibleEvents] = useState(5);
  const [showActivity, setShowActivity] = useState(false);

  return (
    <SidePanel label="Device" onClose={onClose} wide>
        <header className="sticky top-0 z-10 flex items-center justify-between border-b border-hairline bg-[var(--sheet-bg)] px-6 py-3">
          <span className="text-[17px] font-semibold tracking-wide text-ink-3">Device</span>
          <Button data-panel-close variant="plain" className="h-8 px-2 text-[19px] font-semibold text-ink" onClick={onClose}>
            Done
          </Button>
        </header>

        <div className="space-y-6 px-6 pb-10 pt-6">
          <div className="flex items-center gap-5">
            <div className="min-w-0">
              <h2 className="break-words [overflow-wrap:anywhere] text-[28px] font-semibold leading-tight tracking-tight text-ink">{device.label}</h2>
              <p className="mt-1 text-[18px] text-ink-2">
                {[device.vendor, device.model].filter(Boolean).join(" ") || (inferredVendor ? `Possible maker: ${inferredVendor}` : "Unknown maker")}
              </p>
              <div className="mt-2 flex flex-wrap items-center gap-2">
                <Status status={device.status} />
                <Tag tone={device.band === "high" ? "bad" : device.band === "medium" ? "warn" : "ok"}>{bandLabel[device.band]}</Tag>
                
                {device.protected && <Tag>Protected</Tag>}
              </div>
            </div>
          </div>

          <DeviceControls protectedDevice={device.protected} mac={device.mac} policy={policy} pending={pending}
            busy={busy} readOnly={!canAct} onAction={onAction} onWarn={onWarn} />

          {contained && (
            <div className="sheet-notice rounded-2xl border px-4 py-3 text-[18px] leading-relaxed text-ink">
              <span className="font-semibold">Contained, not fixed.</span> Access is restricted. Containment does not establish that malware is present or that the device has been repaired.
            </div>
          )}

          <Section title="Summary">
            <Card className="px-5 py-4"><p className="leading-relaxed text-ink">{summary}</p></Card>
          </Section>
          <DeviceAdvisor key={device.mac} device={device} audioEnabled={audioEnabled} />

          {steps.length > 0 && (
            <Section title="Defend Your Device" action={<ReadAloud text={steps.join(" ")} enabled={audioEnabled} label="Read Device Defenses" iconOnly />} >
              <Card className="divide-y divide-hairline">
                {steps.map((s, i) => (
                  <div key={s} className="flex gap-4 px-5 py-3.5">
                    <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-fill text-[16px] font-semibold text-ink-2">{i + 1}</span>
                    <span className="text-[18px] leading-relaxed text-ink">{s}</span>
                  </div>
                ))}
              </Card>
            </Section>
          )}

          <section>
            <button
              onClick={() => setShowTech((v) => !v)}
              aria-expanded={showTech}
              className="mb-2 flex w-full items-center justify-between px-1 text-[17px] font-semibold tracking-wide text-ink-3"
            >
              Technical Details
              <ChevronDown size={16} className={`transition-transform duration-300 ${showTech ? "rotate-180" : ""}`} aria-hidden />
            </button>
            {showTech && (
              <div className="animate-expand">
                <Card className="divide-y divide-hairline">
                  <Detail label="IP address" value={device.ip} mono />
                  <Detail label="MAC address" value={device.mac} mono />
                  <Detail label="Firmware" value={device.firmware || "Unknown — check device settings"} />
                  <Detail label="Open ports" value={device.ports.length ? device.ports.join(", ") : "None"} />
                  <Detail label="Data in / out" value={`${bytes(device.bytes_in)} / ${bytes(device.bytes_out)}`} />
                  <Detail label="End-of-life" value={yesNo(device.eol)} />
                  <Detail label="Default password" value={yesNo(device.default_creds)} />
                  {device.kev && <Detail label="Known exploited (KEV)" value={device.kev[0].toUpperCase() + device.kev.slice(1)} />}
                  <Detail label="Talks to" value={device.dests.length ? device.dests.join(", ") : "Nothing"} />
                </Card>
              </div>
            )}
          </section>

          <section>
            <button type="button" onClick={() => setShowActivity(value => !value)} aria-expanded={showActivity} aria-controls="device-recent-activity" className="mb-2 flex w-full items-center justify-between px-1 text-[17px] font-semibold tracking-wide text-ink-3">
              Recent Activity<ChevronDown size={16} className={`transition-transform ${showActivity ? "rotate-180" : ""}`} aria-hidden />
            </button>
            {showActivity && <div id="device-recent-activity" className="animate-expand">
            <Card className="divide-y divide-hairline">
              {mine.length === 0 ? (
                <p className="px-5 py-4 text-[18px] text-ink-3">None.</p>
              ) : (
                mine.slice(0, visibleEvents).map((e) => {
                  const m = eventMeta[e.kind];
                  return (
                    <div key={e.id} className="flex items-start gap-3 px-5 py-3">
                      <span className={`mt-[7px] h-1.5 w-1.5 shrink-0 rounded-full ${severityDot[m?.severity ?? "info"]}`} />
                      <div className="min-w-0 flex-1">
                        <div className="flex justify-between gap-3 text-[18px]">
                          <span className="text-ink">{plainEvent(e)}</span>
                          <time className="text-[16px] tabular-nums text-ink-3">{clock(e.ts)}</time>
                        </div>
                        {m && <div className="text-[16px] text-ink-3">{m.label}</div>}
                      </div>
                    </div>
                  );
                })
              )}
            </Card>
              {mine.length>visibleEvents&&<button className="mt-3 underline" onClick={()=>setVisibleEvents(value=>value+5)}>Show More</button>}
            </div>}
          </section>
        </div>
    </SidePanel>
  );
}

function Section({ title, aside, action, children }: { title: string; aside?: string; action?: ReactNode; children: ReactNode }) {
  return (
    <section>
      <div className="mb-2 flex items-baseline justify-between px-1">
        <h3 className="text-[17px] font-semibold tracking-wide text-ink-3">{titleCase(title)}</h3>
        {action}
        {aside && <span className="text-[16px] text-ink-3">{aside}</span>}
      </div>
      {children}
    </section>
  );
}

function Detail({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex flex-col gap-1 px-5 py-3 text-[18px] sm:flex-row sm:items-baseline sm:justify-between sm:gap-6">
      <span className="shrink-0 text-ink-2">{label}</span>
      <span className={`min-w-0 break-words [overflow-wrap:anywhere] text-ink sm:text-right ${mono ? "font-mono text-[17px]" : ""}`}>{value}</span>
    </div>
  );
}
