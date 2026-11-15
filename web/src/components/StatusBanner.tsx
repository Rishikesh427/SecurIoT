import { ShieldAlert, ShieldCheck, TriangleAlert } from "lucide-react";
import type { Issue } from "../lib/issues";
import { Switch } from "./ui";

type Tone = "ok" | "attention" | "critical";

const tones: Record<Tone, { bg: string; ring: string; icon: string; Icon: typeof ShieldCheck }> = {
  ok: { bg: "rgba(40,167,69,0.07)", ring: "rgba(40,167,69,0.22)", icon: "var(--color-ok)", Icon: ShieldCheck },
  attention: { bg: "rgba(232,89,12,0.07)", ring: "rgba(232,89,12,0.25)", icon: "var(--color-sev-high)", Icon: TriangleAlert },
  critical: { bg: "rgba(229,51,42,0.08)", ring: "rgba(229,51,42,0.28)", icon: "var(--color-sev-critical)", Icon: ShieldAlert },
};

/** "Am I okay?" in one glance. The color morphs between states. */
export function StatusBanner({
  issues,
  armed,
  hasPolicy,
  onArm,
  onReview,
}: {
  issues: Issue[];
  armed: boolean;
  hasPolicy: boolean;
  onArm: (v: boolean) => void;
  onReview: () => void;
}) {
  const critical = issues.filter((i) => i.severity === "critical");
  const tone: Tone = critical.length ? "critical" : issues.length ? "attention" : "ok";
  const t = tones[tone];

  const headline =
    tone === "critical"
      ? critical[0].title + "."
      : tone === "attention"
        ? `${issues.length} ${issues.length === 1 ? "thing needs" : "things need"} attention.`
        : "You're protected.";
  const sub =
    tone === "critical"
      ? critical[0].summary
      : tone === "attention"
        ? "Nothing is under attack. Fixing these makes your network safer."
        : "Nothing needs your attention. CasaWarden is watching every device.";

  return (
    <section
      className="flex flex-col gap-4 rounded-[20px] px-6 py-4 md:flex-row md:items-center md:justify-between"
      style={{
        backgroundColor: t.bg,
        boxShadow: `inset 0 0 0 1px ${t.ring}`,
        transition: "background-color 800ms var(--ease-apple), box-shadow 800ms var(--ease-apple)",
      }}
    >
      <div className="flex items-center gap-4">
        <span key={tone} className="animate-fade-in" style={{ color: t.icon }}>
          <t.Icon size={30} strokeWidth={1.9} aria-hidden />
        </span>
        <div className="max-w-[640px]">
          <h1 key={headline} className="animate-fade-in text-[26px] font-semibold leading-tight tracking-[-0.015em] text-ink sm:text-[26px]">
            {headline}
          </h1>
          <p className="mt-0.5 text-[19px] leading-snug text-ink-2">
            {sub}
            {tone !== "ok" && (
              <button onClick={onReview} className="ml-2 font-semibold text-ink underline-offset-4 hover:underline">
                {tone === "critical" ? "What do I do?" : "Review"}
              </button>
            )}
          </p>
        </div>
      </div>
      <div className="flex shrink-0 items-center gap-4 rounded-2xl bg-white/70 px-4 py-2.5 ring-1 ring-hairline backdrop-blur">
        <div>
          <div className="text-[19px] font-medium text-ink">Automatic protection</div>
          <div className="text-[17px] text-ink-2">{!hasPolicy ? "Not available yet" : armed ? "On" : "Off"}</div>
        </div>
        <Switch label="Automatic protection" checked={armed} disabled={!hasPolicy} onChange={onArm} />
      </div>
    </section>
  );
}
