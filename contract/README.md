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
| POST /ingest | Ingest → {accepted_devices, accepted_events} counts | X-API-Key = AGENT_API_KEY; H8–12 |
| GET /sync?etag= | → Sync, or 304 if unchanged and no pending commands | X-API-Key; H8–12 |
| POST /commands/{id}/ack | Ack → 204 | X-API-Key; H8–12 |
| GET /devices | → Device[] | Bearer JWT; H8–12 |
| GET /events | → Event[] newest first | Bearer JWT; H8–12 |
| POST /actions | Action → Command (202) | Bearer JWT; H12–16 |
| GET /policy | → Policy | Bearer JWT; H12–16 |
| PUT /policy | Policy → Policy | Bearer JWT; H12–16 |
| POST /audit/run | empty → {summary: string} | Bearer JWT; H16–20 |
| GET /audit | → AuditEntry[] newest first | Bearer JWT; H16–20 |

Cloud auth is planned, not implemented. Unknown business routes return 404 rather
than pretend to ingest or enforce. Login and persistence belong to H4–8. A command
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
