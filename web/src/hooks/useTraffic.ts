import { useEffect, useRef, useState } from "react";
import type { Device } from "../types";

const POINTS = 30; // about a minute at the 2 s poll

export interface Traffic {
  /** Bytes per second per device, oldest first. */
  byMac: Record<string, number[]>;
  total: number[];
}

/** Turns the cumulative bytes_in/bytes_out counters into per-second rates. */
export function useTraffic(devices: Device[]): Traffic {
  const last = useRef(new Map<string, { bytes: number; at: number }>());
  const [traffic, setTraffic] = useState<Traffic>({ byMac: {}, total: [] });

  useEffect(() => {
    if (!devices.length) return;
    const now = Date.now();
    const rates: Record<string, number> = {};
    for (const d of devices) {
      const bytes = d.bytes_in + d.bytes_out;
      const before = last.current.get(d.mac);
      const secs = before ? Math.max(0.5, (now - before.at) / 1000) : 0;
      rates[d.mac] = before ? Math.max(0, (bytes - before.bytes) / secs) : 0;
      last.current.set(d.mac, { bytes, at: now });
    }
    const sum = Object.values(rates).reduce((a, b) => a + b, 0);
    setTraffic((prev) => ({
      byMac: Object.fromEntries(Object.entries(rates).map(([mac, r]) => [mac, [...(prev.byMac[mac] ?? []), r].slice(-POINTS)])),
      total: [...prev.total, sum].slice(-POINTS),
    }));
  }, [devices]);

  return traffic;
}

export function rate(bps: number): string {
  if (bps < 1024) return `${Math.round(bps)} B/s`;
  if (bps < 1024 * 1024) return `${(bps / 1024).toFixed(bps < 10 * 1024 ? 1 : 0)} KB/s`;
  return `${(bps / 1024 / 1024).toFixed(1)} MB/s`;
}
