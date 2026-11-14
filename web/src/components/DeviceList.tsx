import { ago, isContained } from "../lib/format";
import type { DashDevice } from "../types";
import { Card, Chevron, RiskRing, SectionTitle, Status, Tag } from "./ui";

export function DeviceList({ devices, onSelect, now }: { devices: DashDevice[]; onSelect: (mac: string) => void; now: number }) {
  const sorted = [...devices].sort((a, b) => Number(a.protected) - Number(b.protected) || b.risk - a.risk);
  return (
    <div>
      <SectionTitle action={<span className="text-[13px] text-ink-3">{devices.length} devices</span>}>Devices</SectionTitle>
      <Card className="overflow-hidden">
        <ul className="divide-y divide-hairline">
          {sorted.map((d) => (
            <li key={d.mac}>
              <button
                onClick={() => onSelect(d.mac)}
                className={`flex w-full items-center gap-4 px-5 py-4 text-left transition-colors duration-200 hover:bg-fill/70 ${
                  isContained(d.status) ? "bg-bad/[0.04]" : ""
                }`}
              >
                <RiskRing risk={d.risk} band={d.band} />
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="truncate text-[15px] font-medium text-ink">{d.label}</span>
                    {d.simulated && <Tag>Simulated</Tag>}
                    {d.protected && <Tag>Protected</Tag>}
                  </div>
                  <div className="mt-0.5 truncate text-[13px] text-ink-2">
                    {[d.vendor, d.model].filter(Boolean).join(" ") || "Unknown vendor"}  ·  {d.ip}
                  </div>
                </div>
                <div className="hidden flex-col items-end gap-0.5 sm:flex">
                  <Status status={d.status} />
                  <span className="text-[12px] text-ink-3">{ago(d.last_seen, now)}</span>
                </div>
                <Chevron />
              </button>
            </li>
          ))}
        </ul>
      </Card>
    </div>
  );
}
