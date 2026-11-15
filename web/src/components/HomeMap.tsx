import { lazy, Suspense, useEffect, useRef, useState, type CSSProperties, type ReactNode, type KeyboardEvent, type PointerEvent } from "react";
import type { DashDevice } from "../types";
import type { Theme } from "./ThemeToggle";
const NetworkMap = lazy(() => import("./NetworkMap"));
const DEFAULT_PANEL = 240;
const clamp = (width: number) => Math.max(200, Math.min(360, width));

export function HomeMap({ devices, rates, groups, issueCounts, theme, onSelect, controls, status, bandwidth }: {
  devices: DashDevice[]; rates: Record<string, number>; groups: { safe: number; caution: number; danger: number };
  issueCounts: Record<string, number>; theme: Theme; onSelect: (mac: string) => void; controls: ReactNode; status: ReactNode; bandwidth?: ReactNode;
}) {
  const panel = useRef<HTMLElement>(null);
  const pointer = useRef<number | null>(null);
  const edge = useRef(0);
  const frame = useRef<number | null>(null);
  const pending = useRef(DEFAULT_PANEL);
  const separator = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(DEFAULT_PANEL);
  function paint() {
    panel.current?.style.setProperty('--bandwidth-panel-width', `${pending.current}px`);
    separator.current?.setAttribute('aria-valuenow', String(pending.current));
    separator.current?.setAttribute('aria-valuetext', `Bandwidth panel width ${Math.round(pending.current)} pixels`);
  }
  function finish() {
    if (pointer.current === null) return;
    pointer.current = null;
    if (frame.current !== null) cancelAnimationFrame(frame.current);
    frame.current = null;
    paint(); setWidth(pending.current);
  }
  useEffect(()=>()=>{if(frame.current!==null)cancelAnimationFrame(frame.current);},[]);
  function resize(event: PointerEvent<HTMLDivElement>) {
    if (pointer.current !== event.pointerId) return;
    pending.current = clamp(edge.current - event.clientX);
    if(frame.current!==null)return;
    frame.current=requestAnimationFrame(()=>{frame.current=null;paint();});
  }
  function keyResize(event: KeyboardEvent<HTMLDivElement>) {
    if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
    event.preventDefault();
    const next=event.key === "Home" ? 200 : event.key === "End" ? 360 : clamp(width + (event.key === "ArrowLeft" ? 20 : -20));
    pending.current=next;setWidth(next);
  }
  const columns = { "--bandwidth-panel-width": `${width}px` } as CSSProperties;
  return <div className="space-y-6">
    <header className="flex flex-wrap items-start justify-between gap-4">
      <div><h1 className="t-head">Home</h1><p className="t-body mt-2 text-ink-2">Tap a device for fixes.</p><div className="mt-3">{status}</div></div>
      <div className="flex flex-wrap items-center gap-2">{controls}</div>
    </header>
    <section ref={panel} aria-label="Network Map and Bandwidth" style={columns}
      className={`grid items-start gap-4 ${bandwidth ? "lg:grid-cols-[minmax(0,1fr)_auto]" : "grid-cols-1"}`}>
      <div className="min-w-0 self-center overflow-hidden">
        <Suspense fallback={<div className="flex h-[380px] items-center justify-center text-ink-3">Loading map</div>}>
          <NetworkMap key={theme} devices={devices} rates={rates} issueCounts={issueCounts} onSelect={onSelect} />
        </Suspense>
      </div>
      {bandwidth && <div className="flex w-full min-w-0 items-stretch gap-4 lg:w-auto">
        <div ref={separator} role="separator" aria-label="Adjust Map and Bandwidth Panels" aria-orientation="vertical" tabIndex={0}
          aria-valuemin={200} aria-valuemax={360} aria-valuenow={width} aria-valuetext={`Bandwidth panel width ${width} pixels`}
          title="Drag to resize. Arrow keys adjust; double-click resets."
          className="group relative hidden w-3 shrink-0 self-stretch touch-none cursor-col-resize items-center justify-center rounded-full outline-none focus-visible:ring-2 focus-visible:ring-ink lg:flex"
          onKeyDown={keyResize} onDoubleClick={()=>{pending.current=DEFAULT_PANEL;setWidth(DEFAULT_PANEL);}}
          onPointerDown={event=>{if(event.button!==0||!panel.current)return;event.preventDefault();edge.current=event.clientX+width;pending.current=width;pointer.current=event.pointerId;event.currentTarget.setPointerCapture(event.pointerId);}}
          onPointerMove={resize} onPointerUp={finish} onPointerCancel={finish} onLostPointerCapture={finish}>
          <span className="absolute inset-y-0 left-1/2 w-px bg-hairline transition-colors group-hover:bg-ink-3" />
        </div>
        <aside aria-label="Observed Bandwidth" className="w-full min-w-0 lg:w-[var(--bandwidth-panel-width)]">{bandwidth}</aside>
      </div>}
    </section>
    <div className="grid grid-cols-3 gap-3" aria-label="Device categories">
      {([['safe', 'Safe', 'text-ok'], ['caution', 'Caution', 'text-warn'], ['danger', 'Danger', 'text-bad']] as const).map(([key, label, color]) =>
        <div key={key} className="rounded-2xl border border-hairline p-4">
          <p className={`text-sm font-medium ${color}`}>{label}</p><p className="mt-1 text-3xl font-semibold tabular-nums">{groups[key]}</p>
        </div>)}
    </div>
    <p className="text-xs text-ink-3">A Safe device is not a guarantee of security. Check Prevention to see what you can do to keep your devices secure.</p>
  </div>;
}
