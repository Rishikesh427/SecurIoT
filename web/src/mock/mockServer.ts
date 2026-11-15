// In-browser stand-in for the cloud API (and the agent's feed meta). Speaks the
// /contract shapes and plays the scripted QR attack from the plan's LIVE DEMO,
// so the dashboard works with no hardware or backend.
import type { ActionRequest, AuditEntry, AuditRun, Command, Device, FeedMeta, Policy, SecurEvent, StorageStatus, TokenResponse } from "../types";
import { CAMERA_MAC, defaultPolicy, fixtureDevices, fixtureEvents } from "./fixtures";

type Enforcement = "block_wan" | "quarantine";

const INFECT_DELAY_MS = 2000; // Pi starts infect.sh 2 s after the QR scan
const REJOIN_MS = 12_000; // Pi rejoins Wi-Fi ~10-30 s after Restore

const clone = <T>(v: T): T => structuredClone(v);
const iso = (ms = Date.now()) => new Date(ms).toISOString();
const uuid = () => crypto.randomUUID();

const state = {
  devices: fixtureDevices(),
  events: fixtureEvents(),
  policy: clone(defaultPolicy) as Policy,
  audit: [] as AuditEntry[],
  baseReasons: new Map(fixtureDevices().map((d) => [d.mac, d.reasons])),
  offline: false,
  attackRunning: false,
  lastTick: Date.now(),
  guestJoined: false,
  frozenAt: null as string | null,
};

const device = (mac: string) => state.devices.find((d) => d.mac === mac);

/** Bytes per second a device "uses", so the dashboard's sparklines move. */
function trafficRate(d: Device): number {
  if (d.status === "quarantined" || d.status === "offline") return 0;
  const jitter = () => 0.75 + Math.random() * 0.5;
  switch (d.type) {
    case "camera":
      return (220_000 + (d.anomaly > 0 ? 650_000 : 0)) * jitter(); // video stream, bursts while attacking
    case "phone":
      return Math.random() < 0.3 ? 140_000 * jitter() : 6_000 * jitter();
    case "laptop":
      return 90_000 * jitter();
    default:
      return 2_500 * jitter();
  }
}

function tickTraffic() {
  const now = Date.now();
  const secs = Math.min(10, (now - state.lastTick) / 1000);
  state.lastTick = now;
  for (const d of state.devices) {
    const bytes = Math.round(trafficRate(d) * secs);
    const out = d.type === "camera" ? 0.95 : 0.15;
    d.bytes_out += Math.round(bytes * out);
    d.bytes_in += bytes - Math.round(bytes * out);
  }
}

function audit(e: Omit<AuditEntry, "id" | "ts">) {
  state.audit.unshift({ id: uuid(), ts: iso(), ...e });
}

function pushEvent(e: Omit<SecurEvent, "id" | "source" | "actions_taken" | "would_have"> & Partial<SecurEvent>) {
  state.events.push({ id: uuid(), source: "simulator", actions_taken: [], would_have: [], ...e });
}

function setAnomaly(d: Device, anomaly: number) {
  d.anomaly = anomaly;
  const reasons = [...(state.baseReasons.get(d.mac) ?? [])];
  if (anomaly > 0) reasons.push(`Probing other devices and decoys (+${anomaly})`);
  d.reasons = reasons;
  const base = (state.baseReasons.get(d.mac) ?? []).reduce((s, r) => s + Number(/\(\+(\d+)\)/.exec(r)?.[1] ?? 0), 0);
  d.risk = Math.min(100, base + anomaly);
  d.band = d.risk >= 60 ? "high" : d.risk >= 30 ? "medium" : "low";
  d.confidence = anomaly > 0 ? "high" : "medium";
}

function enforce(d: Device, ladder: Enforcement[]) {
  if (ladder.includes("quarantine")) {
    d.status = "quarantined";
    if (d.mac === CAMERA_MAC) state.frozenAt = iso();
  } else if (ladder.includes("block_wan")) {
    d.status = "wan_blocked";
  }
}

function restore(d: Device) {
  if (d.status === "normal" || d.status === "offline") return;
  const wasQuarantined = d.status === "quarantined";
  d.status = wasQuarantined ? "offline" : "normal"; // a kicked device rejoins Wi-Fi on its own
  if (!wasQuarantined) return;
  setTimeout(() => {
    if (d.status !== "offline") return;
    d.status = "normal";
    d.last_seen = iso();
    setAnomaly(d, 0);
    if (d.mac === CAMERA_MAC) state.frozenAt = null;
  }, d.mac === CAMERA_MAC ? REJOIN_MS : 3000);
}

function guard() {
  if (state.offline) throw new Error("Cloud unreachable (mock outage)");
}

/** Stand-in for GET /events' explanation fields: Gemini "finishes" ~2 s after an incident. */
function mockExplanation(e: SecurEvent, now: number): Pick<SecurEvent, "explanation" | "explanation_status"> {
  const template = { plain_language: `Device showed ${e.kind} behavior.`, recommended_next_step: "Review the device." };
  if (!e.actions_taken.length && !e.would_have.length) return { explanation: template, explanation_status: "template" };
  if (now - Date.parse(e.ts) < 2500) return { explanation: template, explanation_status: "pending" };
  return {
    explanation_status: "ready",
    explanation: e.actions_taken.length
      ? {
          plain_language: "Your living room camera started probing other devices, including a decoy, which is typical of malware. It's been isolated from your network.",
          recommended_next_step: "Unplug and replug the camera, change its default password, then restore it.",
        }
      : {
          plain_language: "Your living room camera started probing other devices, including a decoy, which is typical of malware. Protection is off, so it is still connected.",
          recommended_next_step: "Turn on automatic protection and isolate the camera.",
        },
  };
}

const delay = (ms = 120) => new Promise((r) => setTimeout(r, ms));
const byTsDesc = <T extends { ts: string }>(a: T, b: T) => b.ts.localeCompare(a.ts);

export const mockServer = {
  async login(username: string, password: string): Promise<TokenResponse> {
    await delay(300);
    if (!username || !password) throw new Error("Enter a username and password");
    return { access_token: "mock-jwt", token_type: "bearer", expires_in: 3600 };
  },

  async getDevices(): Promise<Device[]> {
    guard();
    await delay();
    tickTraffic();
    const now = iso();
    for (const d of state.devices) if (d.status === "normal" || d.status === "wan_blocked") d.last_seen = now;
    return clone(state.devices);
  },

  async getEvents(): Promise<SecurEvent[]> {
    guard();
    await delay();
    const now = Date.now();
    return clone([...state.events].sort(byTsDesc).slice(0, 100)).map((e) => ({ ...e, ...mockExplanation(e, now) }));
  },

  async getPolicy(): Promise<Policy> {
    guard();
    await delay();
    return clone(state.policy);
  },

  async putPolicy(p: Policy): Promise<Policy> {
    guard();
    await delay();
    state.policy = clone(p);
    audit({ actor: "judge", action: "policy_update", outcome: "applied" });
    return clone(state.policy);
  },

  async postAction(req: ActionRequest): Promise<Command> {
    guard();
    await delay();
    const cmd: Command = { id: uuid(), created_at: iso(), action: req.action, ...(req.mac ? { mac: req.mac } : {}) };


    const targets = req.action === "restore_all" ? state.devices : [device(req.mac ?? "")].filter(Boolean) as Device[];
    if (!targets.length) throw new Error("Unknown device");
    if (req.action === "quarantine" || req.action === "block_wan") {
      // Same rules as the API's POST /actions (409s).
      if (state.policy.learning_mode) throw new Error("Turn off learning mode before requesting containment");
      if (state.policy.protected_macs.includes(targets[0].mac)) throw new Error("Device is protected");
      if (!state.policy.ladder[req.action]) throw new Error("This ladder step is disabled");
    }

    // Apply the simulated network restriction before recording its result.
    {
      for (const d of targets) {
        if (req.action === "quarantine") enforce(d, ["block_wan", "quarantine"]);
        else if (req.action === "block_wan") enforce(d, ["block_wan"]);
        else restore(d);
      }
      audit({ actor: "simulator", action: req.action, mac: req.mac, command_id: cmd.id, outcome: "applied" });
    }
    return { ...cmd, status: "applied", detail: "Simulated network action completed" };
  },

  async getAudit(): Promise<AuditEntry[]> {
    guard();
    await delay();
    return clone(state.audit);
  },

  async runAudit(): Promise<AuditRun> {
    guard();
    await delay(900);
    const bullets = [
      `Demo only: ${state.events.length} sample ${state.events.length === 1 ? 'alert' : 'alerts'} recorded.`,
      `Simulated devices with access restrictions: ${state.devices.filter(d => d.status === 'quarantined' || d.status === 'wan_blocked').length}. No real network access is changed.`,
      "Review suggested fixes and the audit log. Restoring access does not mean a device is safe.",
    ];
    return { summary: bullets.join("\n"), bullets };
  },

  async getStorage(): Promise<StorageStatus> {
    return { mode: "mock", demo_storage: true, persistent: false, badge: "Demo data" };
  },

  async getFeedMeta(mac: string): Promise<FeedMeta> {
    const d = device(mac);
    if (!d?.has_feed) return { last_ts: null };
    if (state.frozenAt) return { last_ts: state.frozenAt };
    if (d.status === "offline") return { last_ts: d.last_seen };
    return { last_ts: iso() };
  },

  // --- demo controls (mock only) ---

  isOffline: () => state.offline,
  setOffline(v: boolean) {
    state.offline = v;
  },
  attackRunning: () => state.attackRunning,
  guestJoined: () => state.guestJoined,

  /** A new device joins the network (shows the slide-in on the dashboard). */
  simulateNewDevice() {
    if (state.guestJoined) return;
    state.guestJoined = true;
    const mac = "02:00:00:00:00:50";
    const now = iso();
    state.devices.push({
      mac, ip: "10.42.0.61", name: "guest-laptop", label: "Guest laptop", type: "laptop",
      vendor: "Lenovo", model: null, ports: [], bytes_in: 0, bytes_out: 0, dests: [], last_seen: now,
      simulated: true, has_feed: false, eol: false, default_creds: false, cloud_only: false, anomaly: 0,
      risk: 0, band: "low", confidence: "medium", reasons: [], status: "normal",
    });
    state.baseReasons.set(mac, []);
    pushEvent({ mac, ts: now, kind: "new_device", evidence: { simulated: true, ip: "10.42.0.61" } });
  },

  /** Phone scans the QR code on the camera; infect.sh starts 2 s later. */
  simulateQrAttack() {
    const cam = device(CAMERA_MAC)!;
    if (state.attackRunning || cam.status !== "normal") return;
    state.attackRunning = true;

    const at = (ms: number, fn: () => void) => setTimeout(fn, INFECT_DELAY_MS + ms);
    let t0 = 0;
    let decoyAt = 0;

    at(0, () => {
      t0 = Date.now();
      pushEvent({ mac: CAMERA_MAC, ts: iso(t0), kind: "scan_arp", evidence: { simulated: true, arp_requests: 34, window_s: 10 } });
      setAnomaly(cam, 25);
    });
    at(250, () => {
      decoyAt = Date.now();
      setAnomaly(cam, 40);
    });
    at(500, () => {
      pushEvent({ mac: CAMERA_MAC, ts: iso(), kind: "scan_targets", evidence: { simulated: true, distinct_targets: 22, window_s: 10 } });
    });
    // Decoy touch is the trigger. The agent reports it with the action bundle it applied.
    at(1300, () => {
      const armed = !state.policy.learning_mode && !state.policy.protected_macs.includes(CAMERA_MAC);
      const ladder: Enforcement[] = [];
      if (state.policy.ladder.block_wan) ladder.push("block_wan");
      if (state.policy.ladder.quarantine) ladder.push("quarantine");
      const enforcedAt = iso();
      if (armed && ladder.length) enforce(cam, ladder);
      pushEvent({
        mac: CAMERA_MAC,
        ts: iso(decoyAt),
        kind: "decoy_touch",
        evidence: {
          simulated: true,
          destination_ip: "10.42.0.50",
          destination_port: 23,
          learning_mode: !armed,
          first_evidence_at: iso(t0),
          ...(armed && ladder.length ? { enforced_at: enforcedAt } : {}),
        },
        actions_taken: armed ? ladder : [],
        would_have: armed ? [] : ladder,
      });
      for (const action of ladder) audit({ actor: "agent", action, mac: CAMERA_MAC, outcome: armed ? "applied" : "would_have" });
    });
    at(1500, () => {
      pushEvent({ mac: CAMERA_MAC, ts: iso(), kind: "new_domain", evidence: { simulated: true, domain: "update.cam-cloud-cdn.example" } });
      state.attackRunning = false;
    });
  },
};
