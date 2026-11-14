import { useEffect, useState } from "react";
import { ChevronDown } from "lucide-react";
import type { Issue } from "../lib/issues";
import { SeverityTag } from "../lib/severity";
import { Button, Card } from "./ui";

/** "What do I do?" Plain steps, one main action, technical details on request. */
export function FixSheet({
  issue,
  busy,
  onClose,
  onAction,
  onDone,
  onOpenDevice,
}: {
  issue: Issue;
  busy: boolean;
  onClose: () => void;
  onAction: (issue: Issue) => void;
  onDone: (issue: Issue) => void;
  onOpenDevice?: (mac: string) => void;
}) {
  const [showTech, setShowTech] = useState(false);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div className="fixed inset-0 z-40 flex justify-end">
      <div className="absolute inset-0 animate-fade-in bg-black/20 backdrop-blur-[2px]" onClick={onClose} />
      <aside className="relative flex h-full w-full max-w-[480px] animate-sheet-in flex-col overflow-y-auto bg-[#fbfbfd] shadow-[-20px_0_60px_rgba(0,0,0,0.08)]">
        <header className="sticky top-0 z-10 flex items-center justify-between border-b border-hairline bg-[#fbfbfd]/80 px-6 py-3 backdrop-blur-xl">
          <span className="text-[13px] font-medium text-ink-2">How to fix</span>
          <Button variant="plain" className="h-8 px-2 text-[15px] font-semibold text-ink" onClick={onClose}>
            Done
          </Button>
        </header>

        <div className="space-y-6 px-6 pb-10 pt-6">
          <div>
            <SeverityTag severity={issue.severity} />
            <h2 className="mt-3 text-[24px] font-semibold leading-tight tracking-tight text-ink">{issue.title}</h2>
            <p className="mt-2 text-[15px] leading-relaxed text-ink-2">{issue.summary}</p>
          </div>

          <section>
            <h3 className="mb-2 px-1 text-[13px] font-semibold uppercase tracking-wide text-ink-3">Why it matters</h3>
            <Card className="px-5 py-4 text-[15px] leading-relaxed text-ink">{issue.why}</Card>
          </section>

          <section>
            <h3 className="mb-2 px-1 text-[13px] font-semibold uppercase tracking-wide text-ink-3">What to do</h3>
            <Card className="divide-y divide-hairline">
              {issue.steps.map((s, i) => (
                <div key={s} className="flex gap-4 px-5 py-3.5">
                  <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-fill text-[12px] font-semibold text-ink-2">{i + 1}</span>
                  <span className="text-[14px] leading-relaxed text-ink">{s}</span>
                </div>
              ))}
            </Card>
          </section>

          <div className="flex flex-col gap-2">
            {issue.action && (
              <Button variant={issue.action.kind === "isolate" || issue.action.kind === "protect_and_isolate" ? "destructive" : "primary"} className="h-11 w-full" disabled={busy} onClick={() => onAction(issue)}>
                {issue.action.label}
              </Button>
            )}
            <Button className="h-11 w-full" onClick={() => onDone(issue)}>
              I've done this
            </Button>
            {issue.mac && onOpenDevice && (
              <Button variant="plain" className="w-full" onClick={() => onOpenDevice(issue.mac!)}>
                View device
              </Button>
            )}
          </div>

          <section>
            <button
              onClick={() => setShowTech((v) => !v)}
              className="flex w-full items-center justify-between px-1 text-[13px] font-semibold uppercase tracking-wide text-ink-3 hover:text-ink-2"
              aria-expanded={showTech}
            >
              Technical details
              <ChevronDown size={16} className={`transition-transform duration-300 ${showTech ? "rotate-180" : ""}`} aria-hidden />
            </button>
            {showTech && (
              <Card className="mt-2 animate-expand px-5 py-3">
                <ul className="space-y-1 font-mono text-[12px] text-ink-2">
                  {issue.technical.map((t) => (
                    <li key={t}>{t}</li>
                  ))}
                </ul>
              </Card>
            )}
          </section>
        </div>
      </aside>
    </div>
  );
}
