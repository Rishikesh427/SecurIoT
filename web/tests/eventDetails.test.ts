import { describe, expect, it } from "vitest";
import type { SecurEvent } from "../src/types";
import {
  decisionText,
  eventOutcome,
  outcomeSummary,
} from "../src/lib/eventDetails";

function event(overrides: Partial<SecurEvent> = {}): SecurEvent {
  return {
    id: "test",
    mac: "02:00:00:00:00:01",
    ts: "2026-11-14T12:00:00Z",
    kind: "scan_arp",
    evidence: {},
    actions_taken: [],
    would_have: [],
    source: "agent",
    ...overrides,
  };
}

describe("recorded event outcomes", () => {
  it("does not classify an advisory alert as a proposed action", () => {
    const e = event({
      evidence: { decision: "supporting_evidence_only" },
    });

    expect(eventOutcome(e)).toBe("no_action");
    expect(decisionText(e)).toContain("advisory");
  });

  it("recognizes learning-mode proposals", () => {
    expect(eventOutcome(event({
      evidence: { decision: "learning_mode" },
      would_have: ["quarantine"],
    }))).toBe("would_have");
  });

  it("does not present uncertain enforcement as success", () => {
    expect(eventOutcome(event({
      evidence: { enforcement_uncertain: true },
      actions_taken: ["quarantine"],
    }))).toBe("failed");
  });

  it("labels mock actions as simulated", () => {
    expect(outcomeSummary(event({
      source: "simulator",
      actions_taken: ["block_wan"],
    }))).toContain("simulated");
  });

  it("does not invent a safety-gate result", () => {
    expect(decisionText(event())).toBe(
      "No response decision was recorded for this event.",
    );
  });

  it("describes restore as restore, not isolation", () => {
    expect(outcomeSummary(event({
      actions_taken: ["restore"],
    }))).toBe("Reported actions: Restore");
  });
});