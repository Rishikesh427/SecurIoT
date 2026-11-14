# CasaWarden shared contract v3.2

> **Naming:** CasaWarden was previously called SecurIoT. Existing schema IDs,
> metadata, and internal identifiers retain the legacy name so current producers,
> consumers, and stored records remain compatible. The project rename does not
> change API routes or payload fields. See the
> [project naming note](../README.md#project-name-and-compatibility).

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
| GET /devices | → DeviceView[] (rules + dashboard-only AI advice) | Bearer JWT |
| POST /advisor/chat | AdvisorChat → AdvisorAnswer | Bearer JWT; 20 advisor requests/minute/user |
| GET /advisor/triage | → AdvisorTriage | Bearer JWT; same advisor request limit |
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
the validated result as `ready`. Missing credentials, generation failures, queue
saturation, or expired work return `template`. A failed template is never marked
ready or attributed to Gemini. Reads never wait for generation.

The explanation pool has two workers, at most four running/queued jobs, and a
512-entry LRU cache keyed by event ID, sanitized facts, and recorded outcome.
Successful results expire after one hour; failures retry after 60 seconds.
The provider socket timeout is six seconds. Work has an eight-second service
deadline, including queue time; queued calls get only the remaining provider
budget and expired jobs skip Gemini. Late results are discarded. A stalled call stays
inside the work bound until it exits, and subsequent reads show the template.

Gemini sees selected numeric counters, ports, flags and device factors, never
raw packets, raw evidence dictionaries, addresses, names, domains, or banners.
Output is validated for exact fields, nonempty bounded text, word limits, and
known unsupported action/remediation claims. The server appends action wording
from recorded facts. Internet blocking, quarantine, proposed actions, restore,
and simulation have separate wording. These describe reports at event time;
they do not claim the device is currently contained, repaired, or infected.

DeviceView extends the ingest Device with `risk_adjusted` and a strict `ai`
assessment. `risk` and `band` remain authoritative rules values. The displayed
score is `clamp(risk + ai.delta, 0, 100)`, with delta capped at ±10 and forced to
zero for low confidence. Malformed responses use actionable rules advice with
zero adjustment. `ai.status` is `off`, `pending`, `ready`, or `unavailable`;
`ai.source` distinguishes Gemini from rules. `likely_type` is an explicitly
labeled guess for unknown/generic devices and never changes Device.type.
`expected_behavior` is a hypothesis, not measured traffic.

Assessments run in a bounded background queue. Results are cached for 15 minutes
by sanitized facts (including recent event kinds); failures retry after 60 seconds.
The cache holds at most 256 entries. Chat and triage share the queue; saturation
or a request deadline returns 503. Triage considers the 12 highest displayed
scores, then appends remaining devices by score. Failures return the complete
rules order. Requests use opaque IDs rather than device addresses at Gemini.

The model receives allowlisted factors, ports, device name/vendor/model, and
event kinds from up to 1,000 events in the last day. It receives no raw evidence,
destination lists, MACs, or IPs; addresses embedded in text/questions/history are
redacted. Strings are untrusted, and user-supplied chat history is not evidence.
Chat has no tools and cannot change scores, snapshots, commands, or policy.
AI fields are rejected by ingest and never enter agent sync or enforcement.

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
