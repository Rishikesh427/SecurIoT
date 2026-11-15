import { CircleAlert, CircleCheck, Info, OctagonAlert, TriangleAlert, type LucideIcon } from "lucide-react";

export type Severity = "critical" | "high" | "medium" | "low";

export const severityMeta: Record<Severity, { label: string; Icon: LucideIcon; color: string; tint: string; rank: number }> = {
  critical: { label: "Critical", Icon: OctagonAlert, color: "text-sev-critical", tint: "bg-sev-critical/10", rank: 0 },
  high: { label: "High", Icon: TriangleAlert, color: "text-sev-high", tint: "bg-sev-high/10", rank: 1 },
  medium: { label: "Medium", Icon: CircleAlert, color: "text-sev-medium", tint: "bg-sev-medium/10", rank: 2 },
  low: { label: "Low", Icon: Info, color: "text-sev-low", tint: "bg-sev-low/10", rank: 3 },
};

/** Colored icon + label, so severity never relies on color alone. */
export function SeverityTag({ severity }: { severity: Severity }) {
  const m = severityMeta[severity];
  return (
    <span className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[15px] font-semibold ${m.tint} ${m.color}`}>
      <m.Icon size={12} strokeWidth={2.4} aria-hidden />
      {m.label}
    </span>
  );
}

export const OkIcon = CircleCheck;
