# CasaWarden deployment and operation

Reviewed at `332f573` on November 15, 2026. [Recent changes](../docs/RECENT_CHANGES.md)
cover PRs #16–20, validation and known gaps. Existing `securiot` package/schema/
Compose names remain compatibility identifiers.

## Local Compose

Set `.env` and/or `api/.env` from `api/.env.example`. Process variables override
`api/.env`, which overrides the repository `.env` in Python settings; Compose
also supplies its explicit service environment. Do not commit credentials.

Required settings include a random `JWT_SECRET` (at least 32 characters),
`AGENT_API_KEY`, judge account settings, and `DATABASE_URL` for auto/postgres mode.
For intentionally disposable local storage use `STORAGE_MODE=memory`; it still
uses the normal live-only API and does not enable fixture telemetry. Auto/memory
requires one worker (`WEB_CONCURRENCY=1`).

```bash
docker compose up --build -d
```

Open http://localhost (port 80), http://localhost/api/docs and
http://localhost/api/healthz. Caddy strips `/api` before proxying FastAPI. The
`web` service runs Vite against mounted source on internal port 5173 and proxies
API calls to `http://api:8000`; browser access goes through Caddy, not that internal
port. It runs `npm ci` on startup so its persistent dependency volume matches the
lockfile. Source edits hot reload; Dockerfile/package/environment changes can
require rebuild/recreation. A separate `npm run build` checks a production build.
PR #20 restores the frontend export required by Landing; current build/test
results are listed in the audit.

The Compose `gemini_state` volume preserves provider accounting/cache at
`/home/app/.local/state/casawarden/gemini.sqlite3`. Ordinary `docker compose down`
retains named volumes. `down -v` also deletes Gemini accounting/cache and Caddy
state; it is not an ordinary quota-recovery command.

## Database and accounts

`DATABASE_URL` needs a URL-encoded password and the required TLS settings. Set
`JUDGE_USERNAME` (default `judge`) and a random `JUDGE_PASSWORD` of at least
16 characters before initialization. Then explicitly run:

```bash
docker compose build api
docker compose run --rm --no-deps api python -m api.manage init-db
```

Readiness currently requires **migration 6**. The migration chain creates the
`securiot` schema, devices/events/commands/policy/audit/users and migration metadata,
with events using a Timescale hypertable and other domain tables ordinary. Migration
004 adds routine/snapshot support, 005 adds `firmware`/`identification`, and 006
retires simulated device inventory and cancels its pending commands while retaining
historical events/audit. Review that retirement effect before upgrading a shared
fixture/demo database. `GET /readyz` checks actual readiness; `/healthz` is liveness.

Initialization is explicit and transactional; the API does not apply DDL on every
startup. Re-running preserves existing account passwords and policy changes.
Changing `JUDGE_PASSWORD` later does not reset an existing PostgreSQL account.
Passwords are Argon2id hashes. Login uses JSON at `POST /api/auth/login`; use its
Bearer token for `/api/auth/me` and dashboard routes. JWT expiry defaults to
60 minutes and validates issuer/audience/type and active-user identity.

Only login and `/auth/me` are registered. `SIGNUP_INVITE_CODE`, signup UI and tests
exist, but `/auth/signup` currently returns 404. Do not promise invitation signup,
password reset or token refresh. Browser sessions use the legacy localStorage key;
keys/provider credentials must not be stored in frontend environment variables.

## Live-only telemetry and presence

`Settings.load()` enables live-only operation. Simulated ingest returns 409, and
`/devices`, `/events` and `/dashboard` filter retired simulation records. Merely
selecting memory storage does not disable that behavior. The live agent now starts
with discovery and requires Linux enforcement; see
[Linux setup](../agent/LINUX_ENFORCEMENT.md). Agent ingest/sync/ack uses X-API-Key.

Device payloads include optional firmware, identification and snapshot revision.
Upsert ordering uses `snapshot_at`, falling back to `last_seen`. Quiet associated
clients receive an initial seen time so they can be uploaded without a packet. Presence can
advance the snapshot without inventing a newly observed packet. Only normal,
unrestricted absent devices display offline; blocked/quarantined states win.

PostgreSQL ingest checks event UUIDs in a batch and inserts new rows together;
identical retries deduplicate, changed content for a UUID returns 409. Device
selection names contract columns so unrelated future DB columns do not break
strict model validation. Storage status no longer waits on the global DB lock.
These fixes address the freeze described in PR #18; they do not establish a
universal throughput/latency bound.

## Controls, audit and diagnostics

Dashboard JWT requests update policy and create commands with UUID idempotency
keys. `POST /actions` queues a command; `?wait=true` can wait ten seconds for the
agent's reported terminal status. Pending/timeout is not a containment verdict.
The live writer normally polls at 0.5 seconds with error backoff to 30 seconds;
lookup/execution/network timing can delay it. Explicitly protected targets and
disabled steps remain guarded. Manual commands bypass automatic learning/timing
checks; Arm controls automatic response. Policy updates can cancel pending unsafe
containment, and late acknowledgements record actual reports.

`POST /devices/{mac}/warn` is informational audit only. It does not block internet.
Use `block_wan`, `quarantine`, `restore` or `restore_all` for agent actions.
The `SECURIOT_ROUTER_URL` Compose variable and loopback listener class are not wired
to API dispatch/live draining in this revision. See
[Pi direct-control status](../docs/PI_DIRECT_CONTROL.md); a private launcher or
setting an environment variable alone is not a versioned direct-control setup.

`GET /audit` merges detection and command history, with seeded/simulator provenance.
`POST /audit/run` returns a deterministic `summary` plus three consumer `bullets`.
Applied means reported by the agent, not independently verified or repaired.
`GET /dashboard` aggregates devices, explained events, audit, policy and whether
this API process saw a recent sync (within ten seconds). That is distinct from
browser/API connectivity. Authenticated `/diagnostics` reports agent timing,
Gemini configuration/failure and persistent usage state. Timestamps reset with
the API process; the underlying budgets/cache persist in the named volume.

## Gemini advisor: three steps

1. Set server-side `GEMINI_API_KEY` and `GEMINI_MODEL`. Optionally set
   `GEMINI_RESEARCH_MODEL` for grounded public research.
2. Configure a writable persistent `GEMINI_STATE_PATH` if not using Compose's
   default named volume. `GEMINI_DAILY_REQUEST_LIMIT` defaults to 50 attempts/day.
3. Recreate the API with `docker compose up -d --build api`, then inspect
   `/diagnostics` and the device advisor.

Event explanations, advice/chat, prioritization and public research use the shared
provider guard. Automatic dashboard enrichment can consume uncached requests;
provider calls are not limited to explicit chat/research clicks. Attempts are reserved before sending, including failures; cached
results do not spend another attempt. The daily boundary is UTC. Limit 0 blocks
new uncached requests. Identical in-flight requests use leases, successful provider
responses cache for one day, and HTTP 429 opens a 24-hour pause. Missing/unwritable
state fails closed to provider calls; never bypass the guard to clear an error.

Advisor facts cache for one day in-process; fallback results retry after five
minutes. Event explanation caching/deadlines have their own shorter bounds.
Research has a separate single-worker pool and can return pending. Public research
cites documentation and distinguishes published updates from installed firmware;
it must not infer current credentials or change recorded risk/protection.
Displayed AI delta is capped at ±10; rules risk/band and local enforcement remain
separate. Missing configuration, quota, provider/validation failure uses rules.

Chat/triage share a per-user request limit; research starts have a lower limit.
Minimal allowlisted facts are sent, not raw packets/evidence or destination lists.
Chat questions/history still reach the provider after address redaction; public
research uses vendor/model/candidate-family/reported-firmware facts, not LAN identity.

Configuration/usage diagnosis without a provider call:

```bash
docker compose exec api python -m api.diagnose
```

`python -m api.diagnose --gemini` makes one provider request and consumes budget;
use it deliberately, not as an automatic polling probe. Diagnosis may initialize
local accounting state. No real provider call was made for this documentation audit.

## Storage outage and recovery

`STORAGE_MODE=postgres` fails closed on database outage. `auto` can latch into a
single-process in-memory SQLite demo store after connection loss; policy starts
in learning mode, data is temporary, and responses expose storage metadata/badges.
Schema/SQL errors are not successful fallback. `GET /storage` reports mode/reason;
X-Storage-Mode and X-Demo-Storage accompany responses. Memory state is not silently
merged back into PostgreSQL. Restore connectivity/schema, then explicitly restart
to attempt persistent storage again. Do not confuse demo availability with durable
high availability or a healthy connected agent.

## Optional public HTTPS

For a temporary Quick Tunnel (Compose 2.24.4+ port override):

```bash
docker compose -f compose.yaml -f compose.tunnel.yaml up --build -d
docker compose -f compose.yaml -f compose.tunnel.yaml logs tunnel
```

Use the printed HTTPS URL; local Caddy is http://localhost:8080 in this mode.
The hostname can change with tunnel restart. Keep the host awake/online and stop
with the same `-f` arguments. For an owned reachable domain use `SITE_ADDRESS`
with working DNS and ports 80/443 for Caddy; that configuration alone does not
verify a deployed HTTPS site. Agent-local `:8787` dashboard/feed hosting is not
implemented by the current agent.

## Checks

```bash
agent/.venv/bin/python -m pytest agent/tests ml/tests tests -q
npm --prefix web ci
npm --prefix web test
npm --prefix web run build
```

Live database tests are opt-in (`SECURIOT_TEST_DATABASE=1`) after deliberate test
DB initialization. Current local results and known failures are recorded in
[RECENT_CHANGES.md](../docs/RECENT_CHANGES.md#verification-and-known-gaps).
This documentation update does not migrate a DB, deploy containers, run a real
attack or verify Wi-Fi isolation. Private ignored launchers remain local.
