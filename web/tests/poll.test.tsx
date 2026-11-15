import { afterEach, expect, it, vi } from "vitest";
import { act, cleanup, render } from "@testing-library/react";
import { usePoll } from "../src/hooks/usePoll";

function Poll({ fn }: { fn: () => Promise<void> }) { usePoll(fn, 2000); return null; }
afterEach(() => { cleanup(); vi.useRealTimers(); });

it("does not stack requests while a poll is unresolved", async () => {
  vi.useFakeTimers();
  let resolve!: () => void;
  const fn = vi.fn(() => new Promise<void>((done) => { resolve = done; }));
  const view = render(<Poll fn={fn} />);
  await act(async () => { await vi.advanceTimersByTimeAsync(10000); });
  expect(fn).toHaveBeenCalledTimes(1);
  await act(async () => { resolve(); await Promise.resolve(); await vi.advanceTimersByTimeAsync(2000); });
  expect(fn).toHaveBeenCalledTimes(2);
  view.unmount();
  await act(async () => { resolve(); await vi.advanceTimersByTimeAsync(10000); });
  expect(fn).toHaveBeenCalledTimes(2);
});
