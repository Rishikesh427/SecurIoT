# Shared contract v3.2

`schemas.json` is JSON Schema draft 2020-12. Its root validates the ingest batch;
individual types are under `$defs`. `fixtures.json` is a valid ingest batch for
offline mocks. No fixture claims real traffic or enforcement. Refresh timestamps
and generate new event UUIDs for a new replay; retain UUIDs for retries.

Decisions filling gaps in the plan: lowercase colon-delimited MACs, UTC ISO-8601
timestamps, confidence `low|medium|high`, risk bands `low` (0–29), `medium` (30–59),
`high` (60–100), anomaly is points 0–40, reasons are readable strings. Unknown
boolean factors use null. Optional model/kev preserve camera persona data.
Devices are keyed by MAC; events and commands by UUID. An ingest retry must not
duplicate events or replace a newer device snapshot with an older last_seen.

The camera fixture is 75 = possible KEV 15 + EOL 20 + Telnet 15 + default password
25. This is a shared expected result, not an implementation of Person C's scorer.
The decoy event is in learning mode: actions_taken is empty. Every fixture device
is simulated. `devices.yaml` describes intended hardware separately and contains
explicit placeholder MACs, which must be replaced before DHCP/enforcement use.

## Route agreement (future work unless noted)

Caddy supports the plan's bare API routes and `/api/*` (prefix stripped).
The browser uses `/api`; the agent can use the bare routes. Do not combine both
prefixes. `/api/docs` describes only implemented routes, not promised features.

| Route | Request → response | Authorization / milestone |
|---|---|---|
| GET /healthz | → status, service, stage | Public; implemented H1–4 |
| GET /readyz | → {status, database} | Public; implemented H4–8 |
| POST /auth/login | LoginRequest → TokenResponse | Public; implemented H4–8 |
| GET /auth/me | → UserResponse | Bearer JWT; implemented H4–8 |
| POST /ingest | Ingest → {accepted_devices, accepted_events} counts | X-API-Key = AGENT_API_KEY; H8–12 |
| GET /sync?etag= | → Sync, or 304 if unchanged and no pending commands | X-API-Key; H8–12 |
| POST /commands/{id}/ack | Ack → 204 | X-API-Key; H8–12 |
| GET /devices | → Device[] | Bearer JWT; H8–12 |
| GET /events | → EventView[] newest first | Bearer JWT; H8–12 plus H16–20 explanations |
| POST /actions | Action → Command (202) | Bearer JWT; implemented H12–16 |
| GET /policy | → Policy | Bearer JWT; implemented H12–16 |
| PUT /policy | PolicyInput → Policy | Bearer JWT; implemented H12–16 |
| GET /storage | → StorageStatus | Public; implemented H12–16 |
| POST /audit/run | empty → {summary: string} | Bearer JWT; H16–20 |
| GET /audit | → AuditEntry[] newest first | Bearer JWT; H16–20 |

Event views always include a template explanation. When Gemini is configured,
the first read schedules Person C's synchronous `explain(event, device)` function
off the request path and returns `explanation_status: pending`; later reads return
the event-ID-cached result as `ready`. Missing credentials return `template` and
never delay event ingestion or reads.

Audit contains four `seeded-demo` rows plus command lifecycle rows. `/actions`
records `requested`; agent acknowledgement changes the same row to `applied` or
`failed`. Restore is a queued command and the audit does not claim success until
the agent acknowledges it. `/audit/run` passes the newest 1000 audit rows to Person
C's `digest(history)` function. Until that function exists, the route returns 503.

JWT login and the database schema are implemented. Unknown business routes return
404 rather than pretend to ingest or enforce. Login accepts JSON username/password,
returns a bearer access token (60 minutes by default), and /auth/me returns identity.
Missing/invalid credentials return 401; unavailable storage returns 503. A command
is pending until acknowledged; issuing it must not imply successful enforcement.
Repeated acknowledgements should be idempotent. Errors use FastAPI `detail`.
Sync etag is an opaque policy revision; pending commands must still be delivered
when the caller already has that revision. Agent-local GET routes are open;
local actions/policy mutations require localhost or valid JWT as in the plan.

Agent-only feed: POST /feed accepts image/jpeg or image/svg+xml with X-Feed-Token,
X-Device-Name, X-Frame-Ts (UTC ISO timestamp), X-Frame-Seq (integer), and identifies
the device by DHCP source IP. GET /feed/{mac} returns image bytes;
GET /feed/{mac}/meta returns {last_ts: timestamp|null}. Cloud relay is later work.
Feed tokens and agent keys must never appear in VITE_* variables.

H8–12 routes are now implemented. Agent routes require X-API-Key; dashboard reads
require the judge JWT. POST /ingest accepts at most 1000 devices and 1000 events.
Its counts report inserted events and inserted/newer device snapshots; exact
retries return zero. Devices upsert by MAC only when last_seen is newer.
Events deduplicate globally by UUID using a transaction-scoped lock across API
workers. Reusing a UUID with different content (including ts) returns 409 and
rolls back the batch. Events remain immutable after first acceptance.

GET /sync returns an opaque policy-revision etag in JSON and a quoted ETag header.
Pass the JSON value as ?etag=; unchanged policy with no pending commands gives
304. Pending commands always produce 200, even with a matching etag.
POST /commands/{id}/ack accepts Ack and returns 204; /ack?command_id={id} is an
alias. Identical retries succeed; conflicting acknowledgements return 409;
unknown commands return 404. Acknowledgement records the agent's result without
claiming cloud-side enforcement. Commands stop appearing in sync after ack.
GET /devices returns all snapshots ordered by MAC. GET /events returns newest
first with ?limit=100 (1–1000) and ?offset=0 pagination.

H12–16: PUT /policy replaces the policy, defaulting omitted fields to learning
mode ON, an empty protected list, and all ladder steps enabled. If-Match optionally
uses the quoted ETag from GET /policy; stale writes return 412. Policy revision
changes only when values change. Memory etags include a per-process generation
so agents refetch policy after a storage switch/restart.

Actions accept an optional UUID Idempotency-Key header. Reusing it with the same
payload returns the same command without requeueing; changing the payload returns
409. Unknown MACs return 404. Containment requires learning mode OFF, an enabled
ladder step, and an unprotected target. Restore/restore_all remain available.
Policy changes cancel unsafe pending containment; agents must still guard commands
already delivered. Late acknowledgements record the actual execution result.

Storage mode is additive metadata: X-Storage-Mode and X-Demo-Storage are returned
on every response; GET /storage returns details. Existing array and Sync shapes
are unchanged. Memory fallback is temporary, starts with learning ON, and stays
active until an explicit process restart. See deploy/README.md for recovery and
cold-start judge authentication behavior.
