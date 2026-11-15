// Mirrors /contract/schemas.json (v3.2). Timestamps are UTC ISO-8601 strings.

export type Band = "low" | "medium" | "high";
export type Confidence = "low" | "medium" | "high";
export type DeviceStatus = "normal" | "wan_blocked" | "quarantined" | "offline";
export type ActionName = "block_wan" | "quarantine" | "restore" | "restore_all";
export type EventKind = "scan_arp" | "scan_targets" | "decoy_touch" | "new_domain" | "new_device" | "volume";

export interface DeviceAi {
  status: "ready" | "pending" | "unavailable" | "off";
  source: "gemini" | "rules";
  assessment: string;
  likely_type: string;
  expected_behavior: string;
  top_risk: string;
  next_step: string;
  confidence: Confidence;
  delta: number;
  delta_reason: string;
  risk_adjusted: number;
}

export interface AdvisorTurn { role: "user" | "assistant"; text: string }
export interface AdvisorAnswer { source: "gemini" | "rules"; answer: string }
export interface AdvisorTriage { source: "gemini" | "rules"; order: { mac: string; why: string }[] }

export interface Device {
  // Dashboard-only fields (DeviceView). Never send these back to agent ingest.
  risk_adjusted?: number;
  ai?: DeviceAi;
  mac: string;
  ip: string;
  name: string; // short id, e.g. "camera"
  label: string; // display name, e.g. "Living room camera (simulated)"
  type: string;
  vendor: string | null;
  model?: string | null;
  kev?: "confirmed" | "possible" | "none" | "unknown";
  ports: number[];
  bytes_in: number;
  bytes_out: number;
  dests: string[];
  last_seen: string;
  simulated: boolean;
  has_feed: boolean;
  eol: boolean | null;
  default_creds: boolean | null;
  cloud_only: boolean | null;
  anomaly: number;
  risk: number;
  band: Band;
  confidence: Confidence;
  reasons: string[]; // readable, e.g. "Telnet open (+15)"
  status: DeviceStatus;
}

export interface SecurEvent {
  id: string;
  mac: string;
  ts: string;
  kind: EventKind;
  evidence: Record<string, unknown>;
  actions_taken: ActionName[];
  would_have: ActionName[];
  source: "agent" | "simulator";
  // GET /events adds these (EventView). "ready" = Gemini wrote it; "pending" = Gemini
  // is still working and `explanation` is the API's template; "template" = Gemini off.
  explanation?: { plain_language: string; recommended_next_step: string };
  explanation_status?: "pending" | "ready" | "template";
}

export interface Policy {
  learning_mode: boolean;
  protected_macs: string[];
  ladder: { notify: boolean; block_wan: boolean; quarantine: boolean };
}

export interface ActionRequest {
  action: ActionName;
  mac?: string; // omitted for restore_all
}

export interface Command {
  status?: "pending" | "applied" | "failed";
  detail?: string;
  id: string;
  created_at: string;
  action: ActionName;
  mac?: string;
}

export interface AuditEntry {
  id: string;
  ts: string;
  actor: string;
  action: string;
  mac?: string;
  command_id?: string;
  outcome: "requested" | "applied" | "failed" | "would_have";
}

export interface TokenResponse {
  access_token: string;
  token_type: "bearer";
  expires_in: number;
}

export interface AuditRun {
  summary: string;
  bullets?: string[];
}

/** GET /storage: whether data is persisted in Tiger Data or temporary demo storage. */
export interface StorageStatus {
  mode: "postgres" | "memory" | "mock";
  demo_storage?: boolean;
  persistent?: boolean;
  badge?: string;
  reason?: string | null;
  recovery?: string | null;
}

// Agent-only feed metadata.
export interface FeedMeta {
  last_ts: string | null;
}

/** Device plus what the dashboard derives from policy. */
export type DashDevice = Device & { protected: boolean };
