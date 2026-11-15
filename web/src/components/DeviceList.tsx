import { lazy, Suspense, useEffect, useRef, useState } from "react";
import { List, Network } from "lucide-react";
import { rate, type Traffic } from "../hooks/useTraffic";
import { isContained } from "../lib/format";
import type { DashDevice } from "../types";
import { Sparkline } from "./Sparkline";
import { Card, Chevron, RiskRing, SectionTitle, Segmented, Status, Tag } from "./ui";

// Cytoscape is only downloaded when someone opens the map.
const NetworkMap = lazy(() => import("./NetworkMap"));

type View = "list" | "map";
const VIEW_KEY = "securiot.deviceView";

function savedView(): View {
  try {
    return localStorage.getItem(VIEW_KEY) === "map" ? "map" : "list";
  } catch {
    return "list";
  }
}

export function DeviceList({
  devices,
  traffic,
  onSelect,
}: {
  devices: DashDevice[];
  traffic: Traffic;
  onSelect: (mac: string) => void;
}) {
  const [view, setView] = useState<View>(savedView);
  const sorted = [...devices].sort((a, b) => Number(a.protected) - Number(b.protected) || b.risk - a.risk);

  // Devices that appear after the first load slide in and pulse.
  const known = useRef<Set<string> | null>(null);
  const [fresh, setFresh] = useState<Set<string>>(new Set());
  useEffect(() => {
    if (!devices.length) return;
    if (!known.current) {
      known.current = new Set(devices.map((d) => d.mac));
      return;
    }
    const added = devices.filter((d) => !known.current!.has(d.mac)).map((d) => d.mac);
    if (!added.length) return;
    added.forEach((m) => known.current!.add(m));
    setFresh((f) => new Set([...f, ...added]));
    const t = setTimeout(() => setFresh((f) => new Set([...f].filter((m) => !added.includes(m)))), 5000);
    return () => clearTimeout(t);
  }, [devices]);

  const changeView = (v: View) => {
    setView(v);
    try {
      localStorage.setItem(VIEW_KEY, v);
    } catch {
      // per-viewer convenience only
    }
  };

  const latestRates = Object.fromEntries(Object.entries(traffic.byMac).map(([mac, s]) => [mac, s[s.length - 1] ?? 0]));

  return (
    <div>
      <SectionTitle
        action={
          <div className="w-[168px]">
            <Segmented<View>
              value={view}
              onChange={changeView}
              options={[
                { value: "list", label: "List" },
                { value: "map", label: "Map" },
              ]}
            />
          </div>
        }
      >
        <span className="flex items-center gap-2">
          {view === "list" ? <List size={18} aria-hidden /> : <Network size={18} aria-hidden />}
          Devices
        </span>
      </SectionTitle>

      <Card className="overflow-hidden">
        {view === "map" ? (
          <Suspense fallback={<div className="flex h-[440px] items-center justify-center text-[18px] text-ink-3">Loading map</div>}>
            <NetworkMap devices={devices} rates={latestRates} onSelect={onSelect} />
          </Suspense>
        ) : (
          <ul className="divide-y divide-hairline">
            {sorted.map((d) => {
              const series = traffic.byMac[d.mac] ?? [];
              const now = series[series.length - 1] ?? 0;
              const isFresh = fresh.has(d.mac);
              return (
                <li key={d.mac} className={isFresh ? "animate-row-in" : ""}>
                  <button
                    onClick={() => onSelect(d.mac)}
                    className={`flex w-full items-center gap-4 px-5 py-4 text-left transition-colors duration-200 hover:bg-fill/70 ${
                      isContained(d.status) ? "bg-bad/[0.04]" : isFresh ? "bg-ok/[0.05]" : ""
                    }`}
                  >
                    <span className={`rounded-full ${isFresh ? "animate-pulse-ring" : ""}`}>
                      <RiskRing risk={d.risk_adjusted ?? d.risk} band={d.band} />
                    </span>
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="truncate text-[19px] font-medium text-ink">{d.label}</span>
                        {isFresh && <Tag tone="ok">New</Tag>}
                        {d.simulated && <Tag>Simulated</Tag>}
                        {d.protected && <Tag>Protected</Tag>}
                      </div>
                      <div className="mt-0.5">
                        <Status status={d.status} />
                        {d.ai?.status === "ready" && <p className="text-[15px] text-ink-3">Rules {d.risk} · AI {d.ai.delta >= 0 ? "+" : ""}{d.ai.delta} (max ±10)</p>}
                      </div>
                    </div>
                    <div className="hidden flex-col items-end gap-0.5 sm:flex">
                      <Sparkline data={series} muted={d.status === "quarantined" || d.status === "offline"} color={isContained(d.status) ? "var(--color-bad)" : "var(--color-ink-2)"} />
                      <span className="text-[15px] tabular-nums text-ink-3">{rate(now)}</span>
                    </div>
                    <Chevron />
                  </button>
                </li>
              );
            })}
          </ul>
        )}
      </Card>
    </div>
  );
}
