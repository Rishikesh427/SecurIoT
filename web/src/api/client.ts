// One client for both modes. VITE_USE_MOCK=true (the default) uses the in-browser
// mock; otherwise requests go to VITE_API_BASE_URL (/api behind Caddy, or the
// agent's local API on :8787, which serves the same routes).
import { mockServer } from "../mock/mockServer";
import type { ActionRequest, AuditEntry, AuditRun, Command, Device, FeedMeta, Policy, SecurEvent, TokenResponse } from "../types";

export const USE_MOCK = (import.meta.env.VITE_USE_MOCK ?? "true") !== "false";
export const API_BASE = (import.meta.env.VITE_API_BASE_URL ?? "/api").replace(/\/$/, "");

const TOKEN_KEY = "securiot.token";

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

export function getToken(): string | null {
  try {
    return localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setToken(token: string | null) {
  try {
    if (token) localStorage.setItem(TOKEN_KEY, token);
    else localStorage.removeItem(TOKEN_KEY);
  } catch {
    // storage unavailable (private window); session-only login
  }
}

async function http<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = getToken();
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...init.headers,
    },
  });
  if (!res.ok) {
    const body = await res.json().catch(() => null);
    throw new ApiError(res.status, typeof body?.detail === "string" ? body.detail : `${res.status} ${res.statusText}`);
  }
  return res.status === 204 ? (undefined as T) : res.json();
}

export const api = {
  login: (username: string, password: string) =>
    USE_MOCK
      ? mockServer.login(username, password)
      : http<TokenResponse>("/auth/login", { method: "POST", body: JSON.stringify({ username, password }) }),

  devices: () => (USE_MOCK ? mockServer.getDevices() : http<Device[]>("/devices")),
  events: () => (USE_MOCK ? mockServer.getEvents() : http<SecurEvent[]>("/events")),
  policy: () => (USE_MOCK ? mockServer.getPolicy() : http<Policy>("/policy")),
  savePolicy: (p: Policy) => (USE_MOCK ? mockServer.putPolicy(p) : http<Policy>("/policy", { method: "PUT", body: JSON.stringify(p) })),
  action: (req: ActionRequest) =>
    USE_MOCK ? mockServer.postAction(req) : http<Command>("/actions", { method: "POST", body: JSON.stringify(req) }),
  audit: () => (USE_MOCK ? mockServer.getAudit() : http<AuditEntry[]>("/audit")),
  runAudit: () => (USE_MOCK ? mockServer.runAudit() : http<AuditRun>("/audit/run", { method: "POST" })),

  feedMeta: (mac: string) => (USE_MOCK ? mockServer.getFeedMeta(mac) : http<FeedMeta>(`/feed/${encodeURIComponent(mac)}/meta`)),
};
