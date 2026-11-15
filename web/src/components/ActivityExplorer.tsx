import { useEffect, useState } from "react";
import type { Device, SecurEvent } from "../types";
import { ListFilter } from "lucide-react";
import { eventMeta } from "../lib/format";
import {
  eventOutcome,
  outcomeLabels,
  type EventOutcome,
} from "../lib/eventDetails";
import { ActivityList } from "./ActivityList";

const ranges = [
  ["all", "All Events"],
  ["15", "Last 15 minutes"],
  ["60", "Last hour"],
  ["1440", "Last 24 hours"],
  ["10080", "Last 7 days"],
] as const;

export function ActivityExplorer({
  events,
  devices,
  onSelect,
}: {
  events: SecurEvent[];
  devices: Device[];
  onSelect: (mac: string) => void;
}) {
  const [filtersOpen, setFiltersOpen] = useState(false);
  const [device, setDevice] = useState("all");
  const [range, setRange] = useState("all");
  const [kind, setKind] = useState("all");
  const [outcome, setOutcome] = useState("all");
  const [now, setNow] = useState(Date.now());

  // Keep relative-time filters current even when no new events arrive.
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 10_000);
    return () => window.clearInterval(timer);
  }, []);

  const deviceOptions = Array.from(
    new Set([...devices.map((d) => d.mac), ...events.map((e) => e.mac)]),
  ).sort();

  const eventKinds = Array.from(new Set(events.map((e) => e.kind))).sort();

  const cutoff =
    range === "all" ? -Infinity : now - Number(range) * 60_000;

  const filtered = events
    .filter((event) => {
      const timestamp = Date.parse(event.ts);

      return (
        (device === "all" || event.mac === device) &&
        (kind === "all" || event.kind === kind) &&
        (outcome === "all" || eventOutcome(event) === outcome) &&
        (range === "all" ||
          (Number.isFinite(timestamp) && timestamp >= cutoff && timestamp <= now))
      );
    })
    .sort((a, b) => Date.parse(b.ts) - Date.parse(a.ts));

  const selectClass =
    "min-w-0 flex-1 rounded-lg border border-hairline bg-white px-3 py-2 text-sm text-ink";

  function reset() {
    setDevice("all");
    setRange("all");
    setKind("all");
    setOutcome("all");
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-[23px] font-semibold">Recent Activity</h2>
        <button type="button" aria-label="Filter Activity" title="Filters apply to loaded events, not the full server history." aria-expanded={filtersOpen} aria-controls="activity-filters" onClick={() => setFiltersOpen(value => !value)}
          className="flex items-center gap-2 rounded-xl border border-hairline px-4 py-3 transition-transform hover:bg-fill active:scale-95"><ListFilter size={22} /><span>Filters{[device, range, kind, outcome].some(value => value !== 'all') ? ' •' : ''}</span></button>
      </div>
      {filtersOpen && <fieldset id="activity-filters" className="animate-expand space-y-3">
        <legend className="sr-only">Filter Activity</legend>

        <div className="grid gap-3 sm:grid-cols-2">
          <label className="flex min-w-0 items-center gap-3 text-sm">
            Device
            <select
              className={selectClass}
              value={device}
              onChange={(e) => setDevice(e.target.value)}
            >
              <option value="all">All devices</option>
              {deviceOptions.map((mac) => (
                <option key={mac} value={mac}>
                  {devices.find((d) => d.mac === mac)?.label ?? mac}
                </option>
              ))}
            </select>
          </label>

          <label className="flex min-w-0 items-center gap-3 text-sm">
            Time
            <select
              className={selectClass}
              value={range}
              onChange={(e) => setRange(e.target.value)}
            >
              {ranges.map(([value, label]) => (
                <option key={value} value={value}>{label}</option>
              ))}
            </select>
          </label>

          <label className="flex min-w-0 items-center gap-3 text-sm">
            Event Type
            <select
              className={selectClass}
              value={kind}
              onChange={(e) => setKind(e.target.value)}
            >
              <option value="all">All event types</option>
              {eventKinds.map((value) => (
                <option key={value} value={value}>
                  {eventMeta[value]?.label ?? value.replace(/_/g, " ")}
                </option>
              ))}
            </select>
          </label>

          <label className="flex min-w-0 items-center gap-3 text-sm">
            Action Outcome
            <select
              className={selectClass}
              value={outcome}
              onChange={(e) => setOutcome(e.target.value)}
            >
              <option value="all">All outcomes</option>
              {(Object.keys(outcomeLabels) as EventOutcome[]).map((value) => (
                <option key={value} value={value}>
                  {outcomeLabels[value]}
                </option>
              ))}
            </select>
          </label>
        </div>

        <button
          type="button"
          onClick={reset}
          className="mt-3 text-sm font-medium underline"
        >
          Reset
        </button>
      </fieldset>}

      {filtered.length === 0 ? (
        <p className="rounded-xl border border-hairline p-5 text-sm">
          No loaded events match these filters.
        </p>
      ) : (
        <ActivityList key={[device,range,kind,outcome].join(":")}
          events={filtered}
          devices={devices}
          onSelect={onSelect}
        />
      )}
    </div>
  );
}