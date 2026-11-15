import { useEffect, useMemo, useRef, useState } from "react";
import gsap from "gsap";
import { Lock, TriangleAlert } from "lucide-react";
import { Segmented } from "./ui";
import { shortLabel, toMs } from "../lib/format";
import type { DashDevice, SecurEvent } from "../types";

const SIZE = { "1m": 60_000, "5m": 300_000, "1h": 3_600_000 };
type Size = keyof typeof SIZE;
const COLS = 12;
const NAME = ["Quiet", "Notice", "Warning", "Quarantined"];

const levelOf = (e: SecurEvent) =>
  e.actions_taken.includes("quarantine") ? 3
  : e.actions_taken.includes("block_wan") || e.would_have.length || e.kind === "scan_arp" || e.kind === "decoy_touch" ? 2 : 1;

export function Heatmap({ devices, events, now }: { devices: DashDevice[]; events: SecurEvent[]; now: number }) {
  const [size, setSize] = useState<Size>("5m");
  const root = useRef<HTMLDivElement>(null);

  const rows = useMemo(() => devices.map((d) => {
    const cells = Array.from({ length: COLS }, () => ({ lvl: 0, n: 0 }));
    for (const e of events) {
      const t = toMs(e.ts);
      if (e.mac !== d.mac || t == null) continue;
      const i = COLS - 1 - Math.floor((now - t) / SIZE[size]);
      if (i < 0 || i >= COLS) continue;
      cells[i].n++;
      cells[i].lvl = Math.max(cells[i].lvl, levelOf(e));
    }
    const last = cells[COLS - 1];   // current state always shows in the newest column
    if (d.status === "quarantined") last.lvl = 3;
    else if (d.status === "wan_blocked") last.lvl = Math.max(last.lvl, 2);
    return { d, cells };
  }), [devices, events, size, Math.floor(now / 1000)]);

  const hot = rows.filter((r) => r.d.status === "quarantined").length;
  useEffect(() => {
    if (matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const ctx = gsap.context(() => {
      gsap.from("[data-cell]", { scale: 0, opacity: 0, duration: 0.45, ease: "back.out(1.8)", stagger: { each: 0.01, from: "end" } });
      gsap.to('[data-lvl="3"]', { scale: 1.1, repeat: -1, yoyo: true, duration: 0.7, ease: "sine.inOut", delay: 0.8 });
    }, root);
    return () => ctx.revert();
  }, [size, devices.length, hot]);

  const unit = { "1m": "one minute", "5m": "five minutes", "1h": "one hour" }[size];
  return (
    <div ref={root} className="space-y-4">
      <div className="flex items-center justify-between gap-4">
        <h1 className="t-head">Activity</h1>
        <Segmented<Size> value={size} onChange={setSize} options={[{ value: "1m", label: "1 min" }, { value: "5m", label: "5 min" }, { value: "1h", label: "1 hour" }]} />
      </div>
      <p className="t-body text-ink-2">Each square represents {unit}.</p>
      <div className="overflow-x-auto"><div className="min-w-[560px] space-y-2">
        {rows.map(({ d, cells }) => (
          <div key={d.mac} className="flex items-center gap-3">
            <span className="t-sub w-32 shrink-0 truncate">{shortLabel(d.label)}</span>
            <div className="grid flex-1 gap-1" style={{ gridTemplateColumns: `repeat(${COLS}, 1fr)` }}>
              {cells.map((c, i) => (
                <div key={i} data-cell data-lvl={c.lvl} role="img" title={`${NAME[c.lvl]}${c.n ? ` · ${c.n} event${c.n > 1 ? "s" : ""}` : ""}`}
                  aria-label={`${shortLabel(d.label)}, ${NAME[c.lvl]}`}
                  className="grid h-9 place-items-center rounded-md"
                  style={{ background: `var(--heat-${c.lvl})`, color: `var(--heat-ink-${c.lvl || 1})` }}>
                  {c.lvl === 3 ? <Lock size={15} /> : c.lvl > 0 ? <TriangleAlert size={15} /> : null}
                </div>
              ))}
            </div>
          </div>
        ))}
        <div className="t-cap t-mono flex justify-between pl-[140px]"><span>older</span><span>now</span></div>
      </div></div>
      {!rows.length && <p className="t-body text-ink-2">No devices reported yet.</p>}
      <ul className="t-cap flex flex-wrap gap-4">
        {NAME.map((n, i) => (
          <li key={n} className="flex items-center gap-1.5"><span className="h-3 w-3 rounded-sm" style={{ background: `var(--heat-${i})` }} />{n}</li>
        ))}
      </ul>
    </div>
  );
}