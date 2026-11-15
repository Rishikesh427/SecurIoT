import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { Heatmap } from "../src/components/Heatmap";
import type { DashDevice, SecurEvent } from "../src/types";

const now = new Date(2026, 10, 15, 14, 0, 0).getTime();
const device = { mac: "aa", label: "miaow", status: "normal" } as DashDevice;
const at = (minutesAgo: number) => ({ mac: "aa", ts: new Date(now - minutesAgo * 60_000).toISOString(),
  kind: "scan_arp", actions_taken: [], would_have: [], evidence: {} }) as unknown as SecurEvent;
const time = (minutesAgo: number) => new Date(now - minutesAgo * 60_000).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });

beforeEach(() => vi.stubGlobal("matchMedia", vi.fn(() => ({ matches: true }))));
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

it("labels the columns with clock times from oldest to Now", () => {
  render(<Heatmap devices={[device]} events={[]} now={now} />);
  const axis = screen.getByLabelText("Time axis").textContent ?? "";
  // 5-minute squares, 12 columns: labels at 60, 45, 30 and 15 minutes ago, then Now.
  for (const minutes of [60, 45, 30, 15]) expect(axis).toContain(time(minutes));
  expect(axis.trim().endsWith("Now")).toBe(true);
  expect(screen.getByText("← Older")).toBeTruthy();
});

it("gives each square its exact time range", () => {
  render(<Heatmap devices={[device]} events={[at(7)]} now={now} />);
  const squares = screen.getAllByRole("img");
  expect(squares.at(-1)!.getAttribute("title")).toBe(`${time(5)}–now · Quiet`);
  expect(squares.at(-2)!.getAttribute("title")).toBe(`${time(10)}–${time(5)} · Warning · 1 event`);
});
