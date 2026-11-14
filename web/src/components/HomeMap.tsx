import { lazy, Suspense, useEffect, useRef } from "react";
import gsap from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";
import { useCountUp } from "../hooks/useCountUp";
import { isContained } from "../lib/format";
import type { DashDevice } from "../types";
import type { Theme } from "./ThemeToggle";

gsap.registerPlugin(ScrollTrigger);
const NetworkMap = lazy(() => import("./NetworkMap"));

const STEPS = [
  ["1 · Notify", "Low-confidence alerts only tell you. Nothing is blocked."],
  ["2 · Block internet", "Higher confidence cuts the device off from the internet but keeps it on your network."],
  ["3 · Isolate", "A confirmed attack, or any touch on a decoy, cuts the device off completely."],
];

function Stat({ label, value, alert }: { label: string; value: number; alert?: boolean }) {
  const n = useCountUp(value);
  return (
    <div data-hero className="rounded-2xl border border-hairline px-5 py-4">
      <div className="t-cap">{label}</div>
      <div className="t-head t-mono flex items-center gap-2">{n}{alert && value > 0 && <span className="h-2.5 w-2.5 animate-pulse-ring rounded-full bg-bad" />}</div>
    </div>
  );
}

export function HomeMap({ devices, rates, attention, theme, onSelect }: {
  devices: DashDevice[]; rates: Record<string, number>; attention: number; theme: Theme; onSelect: (mac: string) => void;
}) {
  const root = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const ctx = gsap.context(() => {
      gsap.from("[data-hero]", { y: 24, opacity: 0, duration: 0.7, stagger: 0.1, ease: "power3.out" });
      gsap.fromTo("[data-map]", { scale: 0.92, opacity: 0.4, borderRadius: 40 },
        { scale: 1, opacity: 1, borderRadius: 16, ease: "none", scrollTrigger: { trigger: "[data-map]", start: "top 95%", end: "top 40%", scrub: true } });
      gsap.from("[data-step]", { y: 40, opacity: 0, stagger: 0.25, ease: "power2.out",
        scrollTrigger: { trigger: "[data-steps]", start: "top 85%", end: "top 40%", scrub: true } });
      gsap.fromTo("[data-line]", { scaleX: 0 }, { scaleX: 1, transformOrigin: "left", ease: "none",
        scrollTrigger: { trigger: "[data-steps]", start: "top 80%", end: "bottom 60%", scrub: true } });
      root.current!.querySelectorAll<HTMLElement>("[data-step]").forEach((el) => {   // hover: gentle zoom
        const s = gsap.quickTo(el, "scale", { duration: 0.3, ease: "power2.out" });
        el.addEventListener("mouseenter", () => s(1.03));
        el.addEventListener("mouseleave", () => s(1));
      });
    }, root);
    return () => ctx.revert();
  }, []);

  return (
    <div ref={root} className="space-y-16">
      <section className="space-y-4">
        <h1 data-hero className="t-head">Your home network, watched</h1>
        <p data-hero className="t-body max-w-xl text-ink-2">Every device around your router. Links glow while traffic flows and turn red when a device is cut off. Tap a device for details.</p>
        <div className="grid grid-cols-3 gap-4">
          <Stat label="Devices" value={devices.length} />
          <Stat label="Need attention" value={attention} />
          <Stat label="Cut off" value={devices.filter((d) => isContained(d.status)).length} alert />
        </div>
      </section>

      <section data-map className="overflow-hidden border border-hairline bg-white">
        <Suspense fallback={<div className="t-body flex h-[440px] items-center justify-center text-ink-3">Loading map</div>}>
          <NetworkMap key={theme} devices={devices} rates={rates} onSelect={onSelect} />
        </Suspense>
      </section>

      <section data-steps className="space-y-4">
        <h2 className="t-head">How a threat is handled</h2>
        <div className="relative grid gap-4 md:grid-cols-3">
          <div data-line className="absolute left-0 right-0 top-0 h-0.5 bg-bad" />
          {STEPS.map(([h, p]) => (
            <div key={h} data-step className="rounded-2xl border border-hairline p-5 pt-6">
              <h3 className="t-sub">{h}</h3>
              <p className="t-body mt-1 text-ink-2">{p}</p>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}