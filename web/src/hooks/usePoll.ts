import { useEffect, useRef } from "react";

/** One request at a time. Schedule the next poll only after completion. */
export function usePoll(fn: () => void | Promise<void>, ms: number, enabled = true) {
  const saved = useRef(fn);
  saved.current = fn;
  useEffect(() => {
    if (!enabled) return;
    let stopped = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    async function tick() {
      if (document.hidden) { if (!stopped) timer = setTimeout(tick, ms); return; }
      try {
        await saved.current();
      } catch (error) {
        // Consumers should surface errors; keep the poller alive either way.
        console.warn("Dashboard poll failed", error instanceof Error ? error.name : "Error");
      } finally {
        if (!stopped) timer = setTimeout(tick, ms);
      }
    }
    void tick();
    return () => { stopped = true; clearTimeout(timer); };
  }, [ms, enabled]);
}
