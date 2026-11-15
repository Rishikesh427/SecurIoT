import type { Device } from '../types';
import { parseReason } from '../lib/format';

export function RiskBreakdown({ device }: { device: Device }) {
  return <div className="space-y-6">
    <div className="flex items-baseline justify-between gap-4"><h3 className="font-semibold">Underlying Risk</h3><strong className="text-2xl tabular-nums">{device.risk}/100</strong></div>
    <ul className="divide-y divide-hairline">{device.reasons.map((reason, index) => {
      const parsed = parseReason(reason);
      return <li key={index} className="flex justify-between gap-4 py-3"><span>{parsed.text}</span>{parsed.points != null && <strong className="shrink-0 tabular-nums">+{parsed.points}</strong>}</li>;
    })}</ul>
    {!device.reasons.length && <p>No risk factors were recorded. Missing facts do not establish safety.</p>}
    {device.ai && <details className="rounded-xl bg-fill p-4">
      <summary className="cursor-pointer"><span className="inline-flex w-[calc(100%_-_1.5rem)] flex-wrap items-baseline justify-between gap-2">
        <span className="font-semibold">AI Details</span><span className="text-sm font-light text-ink-3">Source: {device.ai.source === 'gemini' ? 'Gemini' : 'Local Rules'}</span>
      </span></summary>
      <div className="mt-4 space-y-5">
        <p className="leading-relaxed">{device.ai.assessment}</p>
        <dl className="grid gap-4 sm:grid-cols-2">
          <div><dt className="text-sm text-ink-3">Suggested Adjustment</dt><dd className="mt-1 font-medium">{device.ai.delta >= 0 ? '+' : ''}{device.ai.delta} points (maximum ±10)</dd></div>
          <div><dt className="text-sm text-ink-3">Status</dt><dd className="mt-1 capitalize">{device.ai.status}</dd></div>
          {device.ai.status === 'ready' && <>
            <div><dt className="text-sm text-ink-3">Confidence</dt><dd className="mt-1 capitalize">{device.ai.confidence}</dd></div>
            <div><dt className="text-sm text-ink-3">Main Concern</dt><dd className="mt-1">{device.ai.top_risk}</dd></div>
            <div className="sm:col-span-2"><dt className="text-sm text-ink-3">Expected Behavior — Hypothesis</dt><dd className="mt-1 leading-relaxed">{device.ai.expected_behavior}</dd></div>
          </>}
        </dl>
        <p className="text-sm text-ink-3">AI advice does not control enforcement.</p>
      </div>
    </details>}
    <p className="text-sm text-ink-3">Reported facts and candidate KEV matches require verification. Neither a score nor AI advice proves compromise.</p>
  </div>;
}
