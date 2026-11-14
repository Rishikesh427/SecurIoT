import { useEffect, useRef, useState } from "react";

const reducedMotion = () => typeof window !== "undefined" && window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;

/** Animates a number from its previous value to `target` (ease-out). */
export function useCountUp(target: number, ms = 700): number {
  const [value, setValue] = useState(() => (reducedMotion() ? target : 0));
  const from = useRef(0);

  useEffect(() => {
    if (reducedMotion()) {
      setValue(target);
      from.current = target;
      return;
    }
    const start = performance.now();
    const begin = from.current;
    let raf = 0;
    const step = (t: number) => {
      const p = Math.min(1, (t - start) / ms);
      setValue(Math.round(begin + (target - begin) * (1 - Math.pow(1 - p, 3))));
      if (p < 1) raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    // Background tabs pause animation frames; always land on the real number.
    const done = setTimeout(() => setValue(target), ms + 50);
    return () => {
      cancelAnimationFrame(raf);
      clearTimeout(done);
      from.current = target;
    };
  }, [target, ms]);

  return value;
}
