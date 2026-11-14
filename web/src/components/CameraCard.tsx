import { useState } from "react";
import { api } from "../api/client";
import { usePoll } from "../hooks/usePoll";
import { ago, toMs } from "../lib/format";
import type { Device } from "../types";
import { Card } from "./ui";

const POLL_MS = 500; // check the feed about twice a second
const STALE_MS = 2000; // frozen when last_ts is older than this

export function CameraCard({ device, now }: { device: Device; now: number }) {
  const [lastTs, setLastTs] = useState<number | null>(null);
  const hasFeed = api.hasFeed();

  usePoll(
    async () => {
      try {
        const meta = await api.feedMeta(device.mac);
        if (meta) setLastTs(toMs(meta.last_ts));
      } catch {
        // keep the last value; the tile will read as frozen
      }
    },
    POLL_MS,
    hasFeed,
  );

  const isolated = device.status === "quarantined";
  const offline = device.status === "offline";
  // Without a feed source (the cloud has no /feed), go by the device's own status.
  const live = hasFeed ? lastTs != null && now - lastTs <= STALE_MS && !isolated && !offline : device.status === "normal" || device.status === "wan_blocked";
  const staleFor = lastTs ? Math.round((now - lastTs) / 1000) : null;

  const [title, subtitle] = isolated
    ? ["Camera isolated", "Cut off from your network and the internet"]
    : offline
      ? ["Camera offline", "Waiting for it to rejoin Wi-Fi"]
      : live
        ? ["Camera running", hasFeed ? "Receiving frames" : `Last seen ${ago(device.last_seen, now).toLowerCase()}`]
        : ["No signal", staleFor != null ? `No frames for ${staleFor}s` : "Waiting for the first frame"];

  return (
    <Card className="overflow-hidden">
      <div className="flex items-center justify-between px-5 pb-3 pt-4">
        <div>
          <div className="text-[15px] font-medium text-ink">{device.label}</div>
          <div className="text-[13px] text-ink-2">{hasFeed ? "Live feed" : "Camera status"}</div>
        </div>
        <span className={`inline-flex items-center gap-1.5 text-[12px] font-medium ${live ? "text-ok" : isolated ? "text-bad" : "text-ink-3"}`}>
          <span className={`h-1.5 w-1.5 rounded-full ${live ? "animate-pulse bg-ok" : isolated ? "bg-bad" : "bg-ink-3"}`} />
          {live ? (hasFeed ? "Live" : "Online") : isolated ? "Isolated" : offline ? "Offline" : "Frozen"}
        </span>
      </div>
      <div className="px-3 pb-3">
        <div
          className={`relative flex aspect-video flex-col items-center justify-center rounded-[14px] transition-colors duration-500 ${
            isolated ? "bg-[#d9d9de]" : "bg-[#e8e8ed]"
          }`}
        >
          <span key={title} className={`animate-fade-in text-[17px] font-semibold tracking-tight ${isolated ? "text-bad" : "text-ink-2"}`}>
            {title}
          </span>
          <span key={subtitle} className="mt-1 animate-fade-in text-[13px] text-ink-3">
            {subtitle}
          </span>
        </div>
      </div>
    </Card>
  );
}
