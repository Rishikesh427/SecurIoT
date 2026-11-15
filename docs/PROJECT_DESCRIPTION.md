# CasaWarden: project reference

Reviewed against `main` at `332f573` on November 15, 2026, including PRs #16–20
merged after 9 p.m. EST on November 14. See [recent changes and verification](RECENT_CHANGES.md).
CasaWarden was previously SecurIoT; existing package, schema, environment and
recovery identifiers stay unchanged for compatibility.

## Purpose and architecture

CasaWarden protects selected smart-device network boundaries through local packet
observation, risk assessment, dashboard review and optional Linux containment.
It is a prototype, not a general malware detector or proof that a low-risk device
is safe. Gemini explains and advises; it does not authorize firewall actions.

| Component | Responsibility |
| --- | --- |
| Agent | Discovery/identity/presence, traffic windows, model/rules/routine, safeguards and enforcement |
| API/storage | JWT auth, telemetry, policy/commands/ack, audit, advisor and storage status |
| ML package | Scan classifier/window, rule detector, risk weights/catalog and advisory helpers |
| Dashboard | Home, Activity, Prevention, device evidence, policy and manual recovery |

Detection/enforcement runs locally. The agent uploads snapshots/events and polls
policy/commands; the dashboard receives API reports. Cloud/provider outages can
interrupt visibility or new controls without making local detection depend on AI.

## Discovery, identity and presence

The public live CLI requires real Linux enforcement plus
`SECURIOT_DISCOVERY_CONFIG`, rejects fixture `--devices`, and starts inventory
from discovery. The current capacity is 20 devices. Sources include captured
LAN source MAC/IPs, DHCP/neighbor hints and AP station information. The separate
reviewed snapshot script remains a utility, not the live CLI's input.

Passive identification combines offline OUI registration, DHCP name/vendor-class
and other bounded hints. Observed listening ports come from the device's own
SYN-ACK source port. A scanned destination port is not a hosted service. Inferred
identity is labeled and does not establish model, installed firmware, credentials
or CVE applicability; private MACs further limit attribution.

Presence uses AP events and station polling. Announced departures have 3 seconds
of grace; silent absence has 15 seconds after observation. Association/source
traffic can restore presence. Unavailable station data does not establish absence.
Quiet associated clients receive an initial seen time even without a packet.
`presence.json` preserves last-seen/offline metadata for relevant rediscovered
records. `snapshot_at` advances presence/assessment updates separately from the
reported observation `last_seen`. Restriction status takes precedence over offline.

## Detection and risk

The saved model is a calibrated histogram gradient-boosting binary scan classifier,
not Isolation Forest. Shared outgoing ten-second windows supply six saved inputs:
`arp, targets, ips, ports, bytes, arp_rate_1s`. The adapter predicts on the first
outgoing packet per observed second, requires two adjacent qualifying seconds,
at least eight ARP/SYN targets, and a ten-second model alert cooldown. Saved
threshold is 0.95; model loading validates feature order/labels/probabilities.

| Finding | Response |
| --- | --- |
| Strong multi-host ARP rule / explicit decoy touch | Can request containment through automatic safeguards |
| Target scan / trained scan warning | Advisory; no model-only automatic quarantine |
| Calibrated volume deviation | Advisory `volume`; no automatic containment |
| Discovery or departure | Inventory/presence evidence, not compromise evidence |

The explicit volume routine calibrates from 30 clean complete ten-second windows
in learning mode. Frozen baselines use a 1,024-byte minimum standard deviation;
volume alerts start at z >= 4. Behavioral signals expire 300 seconds after the
latest signal. Expiry reduces behavioral risk, not an existing restriction.

Static scoring uses reported configuration, service observations and conservative
catalog candidates. Exact vendor/product name matches do not prove affected
firmware. Unknown credentials/firmware stay unknown. Strong ARP/decoy rules can
quarantine directly rather than follow a timed ladder; display risk and AI delta
are separate from the runtime's eligible finding/tier decisions.

The earlier UNSW normal-trace/synthetic-sweep evaluation reported 0.80 episode
recall; that historical dataset result is not independent Pi attack accuracy or
a containment SLA. See [model provenance](../agent/MODEL_HANDOFF.md) and
[coverage limits](../agent/THREAT_COVERAGE.md).

## Enforcement and recovery

The Linux router must host an unbridged routed AP with nftables, an uplink,
and hostapd or NetworkManager/nl80211 control. The backend does not provision Wi-Fi, DHCP, routing or NAT.

| Action | Meaning |
| --- | --- |
| Warn | API audit-only information; no traffic restriction |
| Block Internet | Agent `block_wan`; WAN filtering while local access remains |
| Quarantine | Ethernet filtering plus hostapd deny/deauthentication or nl80211 station removal/upkeep |
| Restore | Remove owned restrictions and permit reconnection |
| Restore all / panic | Attempt known recovery; report partial failures |

Automatic response respects learning/local arming, protection, enabled steps,
30-second warmup, ten-second cooldown and at least 60 seconds Restore grace.
Manual actions override automatic learning/arming and timers; explicit protected
controllers/targets and disabled steps still apply. Default guest automatic
protection differs from explicit manual protection. Learning mode does not undo
saved restrictions. Restore does not repair a device or guarantee immediate rejoin.

Commands use UUID idempotency keys and durable intent/results. The current browser
uses `/actions?wait=true`: queue, wait up to ten seconds, then terminal or pending
result. Normal live sync is scheduled at 0.5 seconds, with backoff to 30 seconds;
this is not an execution deadline. The direct-loopback listener exists but is not
wired into tracked API/live dispatch. See [Pi control status](PI_DIRECT_CONTROL.md).

Replay/simulation use mocks. Real enforcement requires Linux/root, explicit
configuration/discovery and `SECURIOT_REAL_ENFORCEMENT=yes`. Bluetooth shutdown,
power cycling and permanent authentication against MAC changes are not implemented. nl80211 mode
re-kicks reassociated stations roughly once a second; it has no admission deny
list, so validate the possible same-SSID interval on hardware.
[The Linux runbook](../agent/LINUX_ENFORCEMENT.md) covers setup and panic.

## Gemini, UI and backend

Gemini provides asynchronous event explanations, device advice/chat, prioritization
and grounded public-document research. It can label plausible types/names but
cannot change measured identity, enforcement or the authoritative rules score.
AI score adjustment is display-only and capped at ±10. Public research distinguishes
published updates/default policy from installed firmware/current credentials.

Provider calls share persistent SQLite accounting/cache: default 50 attempts per
UTC day, one-day successful cache, 24-hour pause after HTTP 429, fail closed if
accounting storage is unavailable. Compose persists it in `gemini_state`. Advice
fact caching is one day, fallback retry five minutes; event explanations have
separate shorter cache/deadline bounds. Automatic enrichment can spend uncached
requests when the dashboard is read. Rules/template fallbacks remain available.

The dashboard's current tabs are Home, Activity and Prevention, with Settings in
a modal. Home shows map/bandwidth and exclusive Safe/Caution/Danger groups.
Disconnected clients leave Home and appear in Activity's Older Devices; blocked/
quarantined clients stay visible. Activity also includes heatmap, event filters,
a deterministic three-bullet digest and audit log. Detail views expose evidence,
inferred identity, advice/research and manual controls. Theme/audio/tutorial
features are presentation aids, not network probes.

The client is live-only in development and builds. Fixtures/mock modules remain
test helpers; legacy mock flags do not activate the old browser demo. Signup UI
and invite settings exist, but `/auth/signup` is not registered.

Compose runs API, mounted-source Vite and Caddy at http://localhost, with `/api`
proxying. PostgreSQL/TimescaleDB readiness requires migration 6: 004 snapshot/
routine support, 005 identity/firmware, 006 retirement of simulated inventory.
Normal API settings reject simulated ingest and filter simulated reads, including
memory mode. Snapshot upsert uses `snapshot_at` with `last_seen` fallback; events
remain immutable/deduplicated. Batched event ingestion and nonblocking storage
status address the API freeze reported in PR #18.

`/dashboard` aggregates device/event/audit/policy and process-local recent-agent-sync
status. `/diagnostics` reports timing and Gemini usage/failure. Auto storage
fallback is temporary and latched until restart, not transparent durable failover.
Agent-local dashboard/feed hosting at :8787 is not implemented. See
[deployment](../deploy/README.md), [contract](../contract/README.md) and
[dashboard guide](../web/README.md).

## Verification and presentation

Current local test/build failures, known integration gaps and PR-reported hardware
checks are recorded in [RECENT_CHANGES.md](RECENT_CHANGES.md#verification-and-known-gaps).
This documentation review did not retrain the model, contact Gemini, migrate a
DB, run a real attack or validate a radio. Earlier Docker lab passes use synthetic
traffic and, for firewall testing, stubbed hostapd.

Describe suspicious behavior, candidate vulnerabilities and agent-reported outcomes
rather than definite infection, firmware applicability or verified physical repair.
The current model does not establish general malware-family/payload, QR exploit,
DNS-beacon, ARP-reply spoofing or dedicated single-target flood detection.

The supporting guides are the [root README](../README.md),
[agent](../agent/README.md), [integration](../agent/INTEGRATION.md),
[cloud loop](../agent/CLOUD_RUNNER.md), [decoys](../agent/LIVE_DECOYS.md),
[fixture provenance](../agent/fixtures/README.md),
[snapshot discovery](../scripts/STEP2_DISCOVERY.md), and the topic guides linked
above. They describe current code; the private ignored deployment helper is not
a public setup dependency.
