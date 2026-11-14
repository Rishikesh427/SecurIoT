/** Tiny area sparkline. Animates by morphing its path as new points arrive. */
export function Sparkline({
  data,
  width = 72,
  height = 24,
  color = "var(--color-ink-3)",
  muted,
}: {
  data: number[];
  width?: number;
  height?: number;
  color?: string;
  muted?: boolean;
}) {
  const pts = data.length >= 2 ? data : [0, ...data, 0].slice(-2);
  const max = Math.max(...pts, 1);
  const step = width / (pts.length - 1);
  const y = (v: number) => height - 2 - (v / max) * (height - 4);
  const line = pts.map((v, i) => `${i === 0 ? "M" : "L"}${(i * step).toFixed(1)},${y(v).toFixed(1)}`).join(" ");
  const area = `${line} L${width},${height} L0,${height} Z`;
  const stroke = muted ? "var(--color-fill-2)" : color;

  return (
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} className="shrink-0 overflow-visible" aria-hidden>
      <path d={area} fill={stroke} opacity={0.12} style={{ transition: "d 600ms var(--ease-apple)" }} />
      <path d={line} fill="none" stroke={stroke} strokeWidth={1.5} strokeLinejoin="round" strokeLinecap="round" style={{ transition: "d 600ms var(--ease-apple)" }} />
      {!muted && pts.length > 1 && <circle cx={width} cy={y(pts[pts.length - 1])} r={2} fill={stroke} style={{ transition: "cy 600ms var(--ease-apple)" }} />}
    </svg>
  );
}
