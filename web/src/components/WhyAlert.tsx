import type { SecurEvent } from "../types";
import {
  actionNames,
  decisionCode,
  decisionText,
  isSimulated,
  outcomeSummary,
} from "../lib/eventDetails";

export function WhyAlert({ event }: { event: SecurEvent }) {
  const evidence = event.evidence.detection ?? event.evidence;
  const requested = event.evidence.requested_action;

  return (
    <section
      aria-label="Why this alert?"
      className="space-y-3 rounded-xl border border-hairline p-4"
    >
      <h3 className="font-semibold text-ink">Why this alert?</h3>

      <dl className="space-y-2 text-sm text-ink-2">
        <div>
          <dt className="font-medium">Event</dt>
          <dd>{event.kind.replace(/_/g, " ")}</dd>
        </div>

        <div>
          <dt className="font-medium">Recorded at</dt>
          <dd>{new Date(event.ts).toLocaleString()}</dd>
        </div>

        <div>
          <dt className="font-medium">Source</dt>
          <dd>
            {isSimulated(event)
              ? "Simulation / mock enforcement"
              : "Agent-reported event"}
          </dd>
        </div>

        <div>
          <dt className="font-medium">Outcome</dt>
          <dd>{outcomeSummary(event)}</dd>
        </div>

        {typeof requested === "string" && (
          <div>
            <dt className="font-medium">Requested action</dt>
            <dd>{actionNames[requested] ?? requested}</dd>
          </div>
        )}

        <div>
          <dt className="font-medium">Safety-gate / response decision</dt>
          <dd>{decisionText(event)}</dd>
          {decisionCode(event) && (
            <dd className="mt-1 font-mono text-xs">
              {decisionCode(event)}
            </dd>
          )}
        </div>
      </dl>

      <details>
        <summary className="cursor-pointer text-sm font-medium">
          Recorded evidence
        </summary>
        <pre className="mt-2 max-h-64 overflow-auto rounded-lg bg-fill p-3 text-xs">
          {JSON.stringify(evidence, null, 2)}
        </pre>
      </details>

      <p className="text-xs text-ink-3">
        This shows the recorded event and decision. An anomaly alone does not
        establish compromise, and an applied report is not independent proof
        of containment.
      </p>
    </section>
  );
}