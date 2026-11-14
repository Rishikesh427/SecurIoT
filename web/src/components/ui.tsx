import type { ButtonHTMLAttributes, ReactNode } from "react";
import { bandColor, statusStyle } from "../lib/format";
import type { Band, DeviceStatus } from "../types";

export function RiskRing({ risk, band, size = 44 }: { risk: number; band: Band; size?: number }) {
  const stroke = Math.max(3, size / 14);
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  return (
    <div className="relative shrink-0" style={{ width: size, height: size }} aria-label={`Risk ${risk} of 100`}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--color-fill-2)" strokeWidth={stroke} />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke={bandColor[band]}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={c}
          strokeDashoffset={c * (1 - risk / 100)}
          style={{ transition: "stroke-dashoffset 700ms var(--ease-apple), stroke 400ms ease" }}
        />
      </svg>
      <span className="absolute inset-0 flex items-center justify-center font-semibold tabular-nums text-ink" style={{ fontSize: size / 3.3 }}>
        {risk}
      </span>
    </div>
  );
}

export function Status({ status }: { status: DeviceStatus }) {
  const s = statusStyle[status];
  return (
    <span className={`inline-flex items-center gap-1.5 text-[13px] font-medium ${s.text}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${s.dot}`} />
      {s.label}
    </span>
  );
}

export function Tag({ children, tone = "neutral" }: { children: ReactNode; tone?: "neutral" | "bad" | "warn" | "ok" }) {
  const tones = {
    neutral: "bg-fill text-ink-2",
    bad: "bg-bad/10 text-bad",
    warn: "bg-warn/10 text-warn",
    ok: "bg-ok/10 text-ok",
  };
  return <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-medium ${tones[tone]}`}>{children}</span>;
}

export function Card({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <section className={`rounded-[20px] bg-white ring-1 ring-hairline shadow-[0_1px_2px_rgba(0,0,0,0.03),0_8px_28px_rgba(0,0,0,0.04)] ${className}`}>
      {children}
    </section>
  );
}

export function SectionTitle({ children, action }: { children: ReactNode; action?: ReactNode }) {
  return (
    <div className="mb-3 flex items-end justify-between px-1">
      <h2 className="text-[19px] font-semibold tracking-tight text-ink">{children}</h2>
      {action}
    </div>
  );
}

type Variant = "primary" | "secondary" | "destructive" | "plain";
export function Button({ variant = "secondary", className = "", ...props }: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant }) {
  const variants: Record<Variant, string> = {
    primary: "bg-ink text-white hover:bg-black",
    secondary: "bg-fill text-ink hover:bg-fill-2",
    destructive: "bg-bad text-white hover:brightness-95",
    plain: "text-ink-2 hover:text-ink",
  };
  return (
    <button
      {...props}
      className={`inline-flex h-9 items-center justify-center gap-2 rounded-full px-4 text-[14px] font-medium transition-all duration-200 active:scale-[0.97] disabled:pointer-events-none disabled:opacity-35 ${variants[variant]} ${className}`}
    />
  );
}

export function Switch({ checked, onChange, disabled, label }: { checked: boolean; onChange: (v: boolean) => void; disabled?: boolean; label: string }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={`relative h-[31px] w-[51px] shrink-0 rounded-full transition-colors duration-300 disabled:opacity-40 ${checked ? "bg-ok" : "bg-fill-2"}`}
    >
      <span
        className="absolute top-[2px] h-[27px] w-[27px] rounded-full bg-white shadow-[0_3px_8px_rgba(0,0,0,0.15),0_1px_1px_rgba(0,0,0,0.16)] transition-all duration-300"
        style={{ left: checked ? 22 : 2, transitionTimingFunction: "var(--ease-apple)" }}
      />
    </button>
  );
}

/** iOS-style grouped list row. */
export function Row({ label, detail, children, onClick }: { label: ReactNode; detail?: ReactNode; children?: ReactNode; onClick?: () => void }) {
  const Comp = onClick ? "button" : "div";
  return (
    <Comp
      onClick={onClick}
      className={`flex min-h-[52px] w-full items-center justify-between gap-4 px-5 py-3 text-left ${onClick ? "transition-colors hover:bg-fill/70" : ""}`}
    >
      <div className="min-w-0">
        <div className="text-[15px] text-ink">{label}</div>
        {detail && <div className="mt-0.5 text-[13px] text-ink-2">{detail}</div>}
      </div>
      {children}
    </Comp>
  );
}

export function Chevron() {
  return (
    <svg width="8" height="14" viewBox="0 0 8 14" fill="none" className="shrink-0 text-ink-3">
      <path d="M1 1l6 6-6 6" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function Segmented<T extends string>({ value, options, onChange }: { value: T; options: { value: T; label: string }[]; onChange: (v: T) => void }) {
  const idx = options.findIndex((o) => o.value === value);
  return (
    <div className="relative grid rounded-full bg-fill p-[3px]" style={{ gridTemplateColumns: `repeat(${options.length}, minmax(0, 1fr))` }}>
      <span
        className="absolute inset-y-[3px] rounded-full bg-white shadow-[0_1px_3px_rgba(0,0,0,0.1),0_1px_1px_rgba(0,0,0,0.04)] transition-transform duration-300"
        style={{
          width: `calc((100% - 6px) / ${options.length})`,
          left: 3,
          transform: `translateX(${idx * 100}%)`,
          transitionTimingFunction: "var(--ease-apple)",
        }}
      />
      {options.map((o) => (
        <button
          key={o.value}
          onClick={() => onChange(o.value)}
          className={`relative z-10 rounded-full px-4 py-1.5 text-[13px] font-medium transition-colors ${value === o.value ? "text-ink" : "text-ink-2 hover:text-ink"}`}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}
