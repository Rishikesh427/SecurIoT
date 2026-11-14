import { useState } from "react";
import { api } from "../api/client";
import { usePoll } from "../hooks/usePoll";
import type { StorageStatus } from "../types";

/** Where the API keeps data. Demo storage is temporary, so say so. */
export function StorageBadge() {
  const [status, setStatus] = useState<StorageStatus | null>(null);
  const [failed, setFailed] = useState(false);

  usePoll(async () => {
    if (document.hidden) return;
    try {
      setStatus(await api.storage());
      setFailed(false);
    } catch {
      setFailed(true);
    }
  }, 10_000);

  if (failed || !status) return null;
  const [label, dot, title] =
    status.mode === "postgres"
      ? ["Tiger Data", "bg-ok", "Device reports and commands are stored in the database."]
      : status.mode === "memory"
        ? ["Demo storage", "bg-warn", status.reason ?? "Changes are temporary and disappear when the API restarts."]
        : ["Demo data", "bg-ink-3", "Mock mode: built-in sample data, nothing is sent to a server."];

  return (
    <span title={title} className="hidden items-center gap-1.5 rounded-full bg-fill px-3 py-1 text-[12px] font-medium text-ink-2 md:inline-flex">
      <span className={`h-1.5 w-1.5 rounded-full ${dot}`} />
      {label}
    </span>
  );
}
