import { afterEach, expect, it, vi } from "vitest";
afterEach(() => { vi.unstubAllGlobals(); vi.unstubAllEnvs(); vi.resetModules(); });

it("identifies the timed-out route instead of exposing a raw abort message", async () => {
  vi.stubEnv("VITE_USE_MOCK", "false");
  vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new DOMException("signal timed out", "TimeoutError")));
  const { api } = await import("../src/api/client");
  await expect(api.devices()).rejects.toThrow("/devices did not respond within 15s");
});

it("does not claim that the agent is disconnected when an API request fails", async () => {
  vi.stubEnv("VITE_USE_MOCK", "false");
  vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Failed to fetch")));
  const { api } = await import("../src/api/client");
  await expect(api.events()).rejects.toThrow("agent connectivity is unknown");
});

it("does not misidentify an unauthenticated route as an available action", async () => {
  vi.stubEnv("VITE_USE_MOCK", "false");
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("{}", { status: 401 })));
  const { api } = await import("../src/api/client");
  await expect(api.capabilities()).resolves.toEqual({ actions: false, auditRun: false });
});
