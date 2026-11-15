import { lazy, Suspense, type ReactNode } from "react";
import type { DashDevice } from "../types";
import type { Theme } from "./ThemeToggle";
const NetworkMap = lazy(() => import("./NetworkMap"));

export function HomeMap({ devices, rates, groups, issueCounts, theme, onSelect, controls, status }: {
  devices: DashDevice[]; rates: Record<string, number>; groups: { safe: number; caution: number; danger: number };
  issueCounts: Record<string, number>; theme: Theme; onSelect: (mac: string) => void; controls: ReactNode; status: ReactNode;
}) {
  return <div className="space-y-3">
    <header className="flex flex-wrap items-start justify-between gap-4">
      <div><h1 className="t-head">Home</h1><p className="t-body mt-2 text-ink-2">Tap a device for fixes.</p><div className="mt-3">{status}</div></div>
      <div className="flex items-center gap-2">{controls}</div>
    </header>
    <section className="relative overflow-hidden">
      <Suspense fallback={<div className="flex h-[380px] items-center justify-center text-ink-3">Loading map</div>}>
        <NetworkMap key={theme} devices={devices} rates={rates} issueCounts={issueCounts} onSelect={onSelect} />
      </Suspense>
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
