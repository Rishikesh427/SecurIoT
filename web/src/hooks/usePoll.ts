import { useEffect, useRef } from "react";

/** Calls `fn` immediately and then every `ms` while `enabled`. */
export function usePoll(fn: () => void | Promise<void>, ms: number, enabled = true) {
  const saved = useRef(fn);
  saved.current = fn;

  useEffect(() => {
    if (!enabled) return;
    let alive = true;
    const tick = async () => {
      if (alive) await saved.current();
    };
    void tick();
    const id = setInterval(tick, ms);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [ms, enabled]);
}
