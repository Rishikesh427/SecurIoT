import { useEffect, useRef, useState } from "react";
import { History } from "lucide-react";
import { ago, bandLabel, shortLabel } from "../lib/format";
import type { DashDevice } from "../types";
import { Card, Chevron, RiskRing, SectionTitle } from "./ui";

const lastSeen = (ts: string, now: number) => {
  const when = ago(ts, now);
  return when === "Now" ? "just now" : when;
};

/** Previously connected devices: off the Home diagram, still here for history and fixes. */
export function OlderDevices({ devices, now, onSelect }: {
  devices: DashDevice[]; now: number; onSelect: (mac: string) => void;
}) {
  const older = devices
    .filter((d) => d.status === "offline")
    .sort((a, b) => Date.parse(b.last_seen) - Date.parse(a.last_seen));

  // A device that disconnects while this view is open slides in.
  const seen = useRef<Set<string> | null>(null);
  const [fresh, setFresh] = useState<Set<string>>(new Set());
  const macs = older.map((d) => d.mac).join(",");
  useEffect(() => {
    const current = new Set(macs ? macs.split(",") : []);
    if (!seen.current) { seen.current = current; return; }
    const added = [...current].filter((mac) => !seen.current!.has(mac));
    seen.current = current;
    if (!added.length) return;
    setFresh((f) => new Set([...f, ...added]));
    const t = setTimeout(() => setFresh((f) => new Set([...f].filter((m) => !added.includes(m)))), 1500);
    return () => clearTimeout(t);
  }, [macs]);

  return (
    <section aria-label="Older devices">
      <SectionTitle>
        <span className="flex items-center gap-2"><History size={18} aria-hidden />Older devices</span>
      </SectionTitle>
      <p className="t-body -mt-1 mb-3 text-ink-2">Previously connected. Not on your network right now.</p>
      {older.length === 0 ? (
        <p className="text-sm text-ink-3">No disconnected devices. Anything that leaves your network will appear here.</p>
      ) : (
        <Card className="overflow-hidden">
          <ul className="divide-y divide-hairline">
            {older.map((d) => (
              <li key={d.mac} className={fresh.has(d.mac) ? "animate-row-in" : ""}>
                <button onClick={() => onSelect(d.mac)}
                  className="flex w-full items-center gap-4 px-5 py-4 text-left opacity-80 transition-colors duration-200 hover:bg-fill/70 hover:opacity-100">
                  <span className="hidden grayscale sm:inline-flex"><RiskRing risk={d.risk_adjusted ?? d.risk} band={d.band} /></span>
                  <div className="min-w-0 flex-1">
                    <span className="block break-words text-[17px] font-medium text-ink">{shortLabel(d.label)}</span>
                    <span className="text-sm text-ink-3">Last seen {lastSeen(d.last_seen, now)} · {d.ip} · {bandLabel[d.band]}</span>
                  </div>
                  <Chevron />
                </button>
              </li>
            ))}
          </ul>
        </Card>
      )}
    </section>
  );
}
