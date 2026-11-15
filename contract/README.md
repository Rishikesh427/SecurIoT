# CasaWarden shared contract v3.2

Reviewed at `332f573` (November 15, 2026). Existing schema IDs/implementation
identifiers retain SecurIoT names for compatibility. The v3.2 contract has additive
fields; current database readiness is migration **6**, not the original milestone
number. See [deployment](../deploy/README.md) and [recent changes](../docs/RECENT_CHANGES.md).

`schemas.json` is JSON Schema draft 2020-12. Its root validates Ingest; types live
under `$defs`. `fixtures.json` is synthetic test data, not a live-device inventory.
The normal API rejects simulated ingest and filters simulated dashboard records.

## Data and provenance

MACs are lowercase colon-delimited strings, device IP is IPv4, timestamps are UTC
ISO-8601, confidence is `low|medium|high`, anomaly is 0–40 points and risk 0–100.
Bands are low 0–29, medium 30–59, high 60–100. Unknown boolean facts use null.
`type` is an open string, not a closed category enum.

Device includes optional `model`, `kev`, `firmware`, `identification` and
`snapshot_at`. Identity contains labeled passive inference/observed ports and
protection metadata; it is not proof of vendor, installed firmware or credentials.
Firmware/model can remain unknown. Snapshot freshness compares `snapshot_at` or,
when absent, `last_seen`; a presence/assessment change need not invent a packet.

Allowed device status is `normal|wan_blocked|quarantined|offline`. The agent stores
presence separately and exports offline only for absent normal devices. Quiet associated clients can receive an initial seen time without a captured
packet. Existing restriction wins over absence. `present` is not a separate shared payload field.

Event kinds are `scan_arp`, `scan_targets`, `decoy_touch`, `new_domain`, `new_device`
and `volume`. Collection/support in the schema does not establish a detector for
every kind. Events retain immutable UUID/ts/content across retries. Reusing a UUID
with changed content returns 409 and rolls back ingest. Source and evidence label
simulation; proposed actions are `would_have`, reported actions `actions_taken`.

Ingest permits up to 1,000 devices and 1,000 events per batch; the current live
agent/store inventory policy is capped at 20 devices. Device MAC upserts require
a newer snapshot; exact retries report zero accepted changes. PostgreSQL batches
UUID checks/inserts and explicitly selects contract device columns.

## Endpoint map

Paths below are backend paths; Caddy exposes them with `/api` prefixed.

| Route | Auth / result |
| --- | --- |
| `/healthz`, `/readyz`, `/storage` | Public liveness/readiness/storage metadata |
| `POST /auth/login`, `GET /auth/me` | Existing-account login and Bearer identity |
| `POST /ingest` | X-API-Key; accepted device/event counts |
| `GET /sync?etag=...` | X-API-Key; policy plus pending commands, or 304 |
| `POST /commands/{id}/ack` | X-API-Key; applied/failed Ack, 204; `/ack?command_id=` alias |
| `GET /dashboard` | JWT; combined devices/events/audit/policy/agent_connected, ETag |
| `GET /devices`, `GET /events` | JWT; DeviceView/EventView arrays |
| `GET /policy`, `PUT /policy` | JWT; policy with quoted ETag/optional If-Match |
| `POST /actions[?wait=true]` | JWT; queue command, optionally wait for terminal report |
| `POST /devices/{mac}/warn` | JWT; informational audit warning |
| `GET /audit`, `POST /audit/run` | JWT; history and deterministic summary/three bullets |
| `POST /advisor/chat`, `GET /advisor/triage` | JWT; bounded advisory-only responses |
| `POST/GET /advisor/research/{mac}` | JWT; start/poll grounded public-document research |
| `GET /diagnostics` | JWT; process-local agent timings and Gemini status/usage |

`GET /events` is newest-first with limit 1–1,000 and offset. `GET /dashboard`
uses a recent event window and current devices/policy/history; its
`agent_connected` means this API process saw sync within ten seconds, not that
an action succeeded. The aggregate/research/diagnostic/wait-result envelopes are
implemented routes, not all separate named `$defs`; validate component contracts
where supplied and inspect route models for additive envelopes.

## Commands, overrides and policy

Actions are `block_wan`, `quarantine`, `restore`, `restore_all`. Every action
except restore_all requires MAC; restore_all must omit it. UUID Idempotency-Key
reuses the same queued command for identical content; different content returns
409. Unknown targets return 404. Live-only controls reject simulated inventory
and explicitly manually protected controller identity where available.

Default POST /actions returns 202. With `wait=true`, the API waits up to ten
seconds: a terminal result can return 200 with status/detail, otherwise it returns
pending. The browser's timeout is longer. Queueing/timeouts alone are not
containment outcomes. Agent sync/ack remains the supported execution path; the
prepared loopback direct listener/router URL is not wired into dispatch.

Manual containment bypasses automatic learning/arming/warmup/cooldown/grace;
explicit protected targets and disabled steps remain guarded. Restore works
independently of learning mode. Policy updates can cancel unsafe pending
containment and cannot recall an already delivered action. Late acknowledgements
record actual reports. Identical Ack retries succeed; conflicting ones return
409. Local command journals prevent repeating an already processed UUID.

Sync has an opaque policy etag in JSON and quoted ETag header. Pending commands
produce 200 even when etag matches; unchanged/no work can return 304. PUT /policy
replaces values and optional If-Match prevents stale writes (412). Defaults are
learning mode on, no protected MACs and enabled ladder steps. Memory revisions
include a generation so agents refetch after storage switches/restarts.

## Advice, audit and storage boundaries

EventView adds a template/generated explanation and status. DeviceView adds
rules risk/band plus `risk_adjusted` and `ai`; snapshot/identity/firmware are valid
there too. AI delta is display-only, capped at ±10, and zero for low confidence.
Hypothesized type/behavior is labeled, not measured. Chat has no action tools.
Public research cites documentation without verifying installed firmware/current
password or modifying scores. These output-only AI fields are rejected by ingest
and do not enter agent enforcement.

All Gemini calls share a persistent request budget/cache in SQLite. Default is
50 attempts/day at UTC boundaries, successful provider cache one day, HTTP 429
pause 24 hours; storage failure blocks provider calls. Advice uses one-day fact
caching/five-minute fallback retry. API limits and bounded queues remain separate
from deployment-wide request accounting. See deployment for state volume/diagnosis.

Audit merges command lifecycle and detection activity, with optional event_id.
Run Audit returns deterministic `summary` plus three `bullets`; no Gemini call is
required. Applied is a report, not independent containment verification. Seeded
and simulator entries remain distinguishable from live activity.

Storage metadata uses X-Storage-Mode/X-Demo-Storage and `/storage`. Auto fallback
is temporary and latched until process restart; it is not silently merged back.
Schema 005 adds identity/firmware; 006 removes simulated inventory/cancels its
pending actions without deleting historical event/audit rows.

## Not implemented by these contracts alone

The `/auth/signup` invitation flow is not registered despite UI/env/test scaffolding.
Agent-local `:8787` dashboard and POST/GET image feed remain planned interfaces,
not active cloud/local services. Bluetooth control, power cycling and general
malware/firmware verification are absent. Legacy feed token/header examples do
not establish a working feed endpoint. Current build/test gaps are in
[the review](../docs/RECENT_CHANGES.md#verification-and-known-gaps).
