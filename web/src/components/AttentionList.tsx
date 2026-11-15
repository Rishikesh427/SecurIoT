import { Wrench } from "lucide-react";
import type { Issue } from "../lib/issues";
import { OkIcon, SeverityTag, severityMeta } from "../lib/severity";
import { Button, Card, SectionTitle } from "./ui";

/** "What's wrong?" Each item is plain language with a Fix button. */
export function AttentionList({ issues, onFix }: { issues: Issue[]; onFix: (issue: Issue) => void }) {
  return (
    <div id="attention">
      <SectionTitle action={issues.length ? <span className="text-[17px] text-ink-3">Most urgent first</span> : undefined}>
        Protect your devices
      </SectionTitle>
      <Card className="overflow-hidden">
        {issues.length === 0 ? (
          <div className="flex items-center gap-3 px-5 py-5 text-[19px] text-ink-2">
            <OkIcon size={20} className="text-ok" aria-hidden />
            Nothing needs your attention right now.
          </div>
        ) : (
          <ul className="divide-y divide-hairline">
            {issues.map((issue) => {
              const m = severityMeta[issue.severity];
              return (
                <li key={issue.id} className="flex animate-row-in items-center gap-4 px-5 py-4">
                  <span className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-full ${m.tint} ${m.color}`}>
                    <m.Icon size={18} strokeWidth={2.2} aria-hidden />
                  </span>
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-[19px] font-medium text-ink">{issue.title}</span>
                      <SeverityTag severity={issue.severity} />
                    </div>
                  </div>
                  <Button variant={issue.severity === "critical" ? "primary" : "secondary"} onClick={() => onFix(issue)} className="shrink-0">
                    <Wrench size={14} aria-hidden />
                    Fix
                  </Button>
                </li>
              );
            })}
          </ul>
        )}
      </Card>
    </div>
  );
}
