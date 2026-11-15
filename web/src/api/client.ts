// One client for both modes. Mock mode (in-browser, no backend) is the default
// for `npm run dev`; production builds talk to the API unless VITE_USE_MOCK=true.
import { mockServer } from "../mock/mockServer";
import type { ActionRequest, AdvisorAnswer, AdvisorTriage, AdvisorTurn, AuditEntry, AuditRun, Command, Device, FeedMeta, Policy, SecurEvent, StorageStatus, TokenResponse } from "../types";

const env = import.meta.env;

// VITE_MOCK_MODE is the name the Docker build (web/Dockerfile) passes; VITE_USE_MOCK also works.
const mockSetting = env.VITE_USE_MOCK ?? env.VITE_MOCK_MODE;
export const USE_MOCK = mockSetting != null ? mockSetting === "true" : env.DEV;
/** Caddy serves the API under /api (prefix stripped); `npm run dev` proxies /api the same way. */
export const API_BASE = (env.VITE_API_URL ?? env.VITE_API_BASE_URL ?? "/api").replace(/\/$/, "");
/** The camera feed lives only on the agent (e.g. http://10.42.0.1:8787). Unset = no feed polling. */
export const FEED_BASE = env.VITE_FEED_URL?.replace(/\/$/, "") ?? null;

const TOKEN_KEY = "securiot.token";

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

/** The server doesn't have this route yet (later milestone). */
export const isMissing = (e: unknown) => e instanceof ApiError && (e.status === 404 || e.status === 501);

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

function authHeaders(): Record<string, string> {
  const token = getToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

let policyETag: string | null = null;

async function http<T>(path: string, init: RequestInit = {}, base = API_BASE): Promise<T> {
  const timeoutMs = path === "/audit/run" ? 30000 : 15000;
  try {
    const res = await fetch(`${base}${path}`, {
      ...init, signal: init.signal ?? AbortSignal.timeout(timeoutMs), cache: "no-store",
      headers: { "Content-Type": "application/json", ...authHeaders(), ...init.headers },
    });
    if (!res.ok) {
      const body = await res.json().catch(() => null);
      throw new ApiError(res.status, typeof body?.detail === "string" ? body.detail : `${res.status} ${res.statusText}`);
    }
    if (path === "/policy") policyETag = res.headers.get("ETag");
    if (res.status === 204) return undefined as T;
    if (!res.headers.get("content-type")?.includes("json")) throw new ApiError(404, "Not an API response; check API routing.");
    return await res.json();
  } catch (error) {
    if (error instanceof ApiError) throw error;
    const name = error && typeof error === "object" && "name" in error ? String(error.name) : "";
    const route = path.split("?")[0];
    if (name === "TimeoutError" || name === "AbortError") {
      throw new ApiError(0, `${route} did not respond within ${timeoutMs / 1000}s. Check the API/database connection. A submitted command may still have been received.`);
    }
    throw new ApiError(0, `Cannot reach ${route}. Check the API connection; agent connectivity is unknown.`);
  }
}

/**
 * Whether a POST-only route exists, without calling it: FastAPI answers GET on
 * an existing POST route with 405 and on an unknown route with 404.
 */
async function routeExists(path: string): Promise<boolean> {
  const res = await fetch(`${API_BASE}${path}`, { headers: authHeaders(), signal: AbortSignal.timeout(8000) }).catch(() => null);
  return !!res && (res.ok || res.status === 405);
}

export const api = {
  login: (username: string, password: string) =>
    USE_MOCK
      ? mockServer.login(username, password)
      : http<TokenResponse>("/auth/login", { method: "POST", body: JSON.stringify({ username, password }) }),

  devices: () => (USE_MOCK ? mockServer.getDevices() : http<Device[]>("/devices")),
  advisorChat: (mac: string, question: string, history: AdvisorTurn[]) =>
    http<AdvisorAnswer>("/advisor/chat", { method: "POST", body: JSON.stringify({ mac, question, history }) }),
  advisorTriage: () => http<AdvisorTriage>("/advisor/triage"),
  events: () => (USE_MOCK ? mockServer.getEvents() : http<SecurEvent[]>("/events?limit=100")),
  policy: () => (USE_MOCK ? mockServer.getPolicy() : http<Policy>("/policy")),
  savePolicy: (p: Policy) => {
    if (USE_MOCK) return mockServer.putPolicy(p);
    if (!policyETag) return Promise.reject(new ApiError(409, "Reload settings before changing the response policy."));
    return http<Policy>("/policy", { method: "PUT", headers: {"If-Match": policyETag}, body: JSON.stringify(p) });
  },
  action: (req: ActionRequest) =>
    USE_MOCK ? mockServer.postAction(req) : http<Command>("/actions", { method: "POST", headers: {"Idempotency-Key": crypto.randomUUID()}, body: JSON.stringify(req) }),
  audit: () => (USE_MOCK ? mockServer.getAudit() : http<AuditEntry[]>("/audit")),
  runAudit: () => (USE_MOCK ? mockServer.runAudit() : http<AuditRun>("/audit/run", { method: "POST" })),

  /** Where the API keeps data: Tiger Data, or temporary demo storage. Public route. */
  storage: () => (USE_MOCK ? mockServer.getStorage() : http<StorageStatus>("/storage")),

  /** Which write routes the server supports so far. */
  capabilities: async () =>
    USE_MOCK
      ? { actions: true, auditRun: true }
      : Promise.all([routeExists("/actions"), routeExists("/audit/run")]).then(([actions, auditRun]) => ({ actions, auditRun })),

  hasFeed: () => USE_MOCK || FEED_BASE != null,
  /** null when there's no feed source configured. */
  feedMeta: (mac: string): Promise<FeedMeta> | null =>
    USE_MOCK ? mockServer.getFeedMeta(mac) : FEED_BASE ? http<FeedMeta>(`/feed/${encodeURIComponent(mac)}/meta`, {}, FEED_BASE) : null,
};
