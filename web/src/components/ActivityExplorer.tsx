import { useEffect, useState } from "react";
import type { Device, SecurEvent } from "../types";
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
    "mt-1 w-full rounded-lg border border-hairline bg-white px-3 py-2 text-sm text-ink";

  function reset() {
    setDevice("all");
    setRange("all");
    setKind("all");
    setOutcome("all");
  }

  return (
    <div className="space-y-4">
      <fieldset className="rounded-xl border border-hairline p-4">
        <legend className="px-1 text-sm font-medium">Filter activity</legend>

        <div className="grid gap-3 sm:grid-cols-2">
          <label className="text-sm">
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

          <label className="text-sm">
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

          <label className="text-sm">
            Event type
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

          <label className="text-sm">
            Action outcome
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
          Reset filters
        </button>
      </fieldset>

      <p className="text-xs text-ink-3" role="status">
        Showing {filtered.length} of {events.length} loaded events.
        Filters do not search older server history or the separate command audit log.
      </p>

      {filtered.length === 0 ? (
        <p className="rounded-xl border border-hairline p-5 text-sm">
          No loaded events match these filters.
        </p>
      ) : (
        <ActivityList
          events={filtered}
          devices={devices}
          onSelect={onSelect}
        />
      )}
    </div>
  );
}