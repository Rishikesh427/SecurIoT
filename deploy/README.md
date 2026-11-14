# Person B: hours 1–20

The API/web hosting runs locally, without a paid hosting service. FastAPI runs in one
container; Caddy serves a static bundle and proxies the API in another.
Docker Engine + Compose on Linux are suitable; on Windows use Docker Desktop
with Linux containers (subject to its license). No Vultr dependency.

## Audit and digest

The dashboard's Generate digest button calls authenticated `POST /api/audit/run`.
The deterministic digest works offline without Gemini. It summarizes the latest
1,000 audit entries, not a guaranteed full week, and separates recorded activity,
simulator reports, and seeded demo examples. Pending requests, failed actions,
learning-mode proposals, and acknowledged outcomes are counted separately.

`GET /api/audit` combines dashboard command records with detection and action
records derived from stored events. Event rows include `event_id` and stable IDs;
repeated ingest does not duplicate history. Existing stored events are included
without a migration. The event timestamp is the report timestamp, not a separately
measured enforcement time. Applied outcomes are agent reports, not verification
of physical containment or current device safety.

Run `python -m pytest tests/test_audit_explanations.py ml/tests/test_digest.py -q`
for the authenticated detection, containment, Restore, acknowledgement, and digest
round trip. The PostgreSQL audit test in `tests/test_database.py` is opt-in with
`SECURIOT_TEST_DATABASE=1` and rolls back its writes.

## Local start

From the repository root, copy `.env.example` to `.env` and `api/.env.example` to
`api/.env` only if those files do not already exist. Configure the database and
judge settings described below, initialize the schema, then:

```sh
docker compose up --build -d
curl --fail http://localhost/api/healthz
```

Open http://localhost for the React/TypeScript dashboard and
http://localhost/api/docs for the API. Caddy's multi-stage image builds `web/`
and includes its production bundle. `WEB_BUNDLE_PATH` is no longer used.
After frontend changes, rebuild Caddy:

```sh
docker compose up --build -d caddy
```

The API image copies only source, migrations, and requirements. It runs as a
non-root user, has a process healthcheck, and does not publish port 8000. Compose
injects `api/.env` into the API container only; no secrets enter the image or web
bundle. `/api/healthz` is liveness; `/api/readyz` also checks database initialization.
With STORAGE_MODE=auto, connection loss switches to explicit demo memory storage;
readiness and every response identify the storage mode. STORAGE_MODE=postgres
keeps fail-closed 503 behavior. Missing migrations and SQL errors do not trigger fallback.

## Tiger Data and the judge login

Use your existing Tiger Data connection in DATABASE_URL, preserving its TLS
settings (`sslmode=require` or stronger). This setup does not provision a paid
database or assume a free trial lasts forever. The H4–8 task requires an existing
PostgreSQL database with TimescaleDB; H12–16 adds an in-memory SQLite demo fallback.

Required settings in ignored `api/.env`:

- DATABASE_URL: the PostgreSQL connection URI; URL-encode special password characters.
- JWT_SECRET: a random secret of at least 32 characters; never a VITE_* variable.
- JUDGE_USERNAME: `judge` by default.
- JUDGE_PASSWORD: a random password of at least 16 characters for seeding and cold-start demo login.
- JWT_EXPIRE_MINUTES: 60 by default, configurable from 1 to 1440.

Local Python loads `api/.env` relative to the module, with process environment
variables taking precedence. Compose uses `api/.env`; its explicit APP_ENV and
ROOT_PATH override that file. CORS_ORIGINS belongs in `api/.env`, not root `.env`.

Initialize explicitly (the API does not run DDL at every startup):

```sh
docker compose build api
docker compose run --rm --no-deps api python -m api.manage init-db
```

Or from the repository root with Python: `python -m api.manage init-db`.
This transaction creates schema `securiot`, the five domain tables, the supporting
`users` table, and migration metadata. It invokes `create_hypertable` exactly once
for events on ts. Devices, commands, policy, audit, and users remain ordinary
tables. It seeds a single learning-mode policy and stores only an Argon2id hash
for the judge password. Fixture devices/events are not loaded into live storage.
The migration and judge seed are safe to rerun; existing credentials, disabled
accounts, and policy changes are preserved. Changing JUDGE_PASSWORD later does
not reset an existing database account. Migration failure rolls back the batch.

The events key is `(id, ts)` because hypertable uniqueness must include its time
dimension. Future ingest must retain the original timestamp on retries and enforce
the UUID-to-timestamp invariant; the schema alone does not reject a reused UUID
with a different timestamp. Foreign keys from events to devices are intentionally
absent so an event can arrive before its device snapshot.

H8–12 now enforces that invariant in the ingest transaction: concurrent API
ingests serialize the UUID check, exact retries are accepted without duplicates,
and changed content for the same UUID returns 409 with the whole batch rolled back.

Login sends JSON to POST `/api/auth/login`:

For a direct PowerShell login check, run `./scripts/Test-JudgeLogin.ps1` from the
repository root. It reads the judge credentials from `api/.env`, removes the
surrounding dotenv quotes, and stops if login fails. It prints identity only.
In Swagger's HTTP Bearer Authorize box, paste only the token, without `Bearer `.

```json
{"username":"judge","password":"<JUDGE_PASSWORD from api/.env>"}
```

The response is `{access_token, token_type: "bearer", expires_in}`. Send
`Authorization: Bearer <access_token>` to GET `/api/auth/me` for `{id, username, role}`.
Swagger at `/api/docs` can call login, then accept the returned token through
Authorize. JWTs validate HS256 signature, expiry, issuer, audience, access-token
type, and the user's active status. Login errors use the same 401 for missing
users and wrong passwords. Database errors return a generic 503 without connection
details. No refresh token, registration, password-reset flow, or login UI is part
of this milestone. `api.main.current_user` is reusable on later protected routes.

## Free public HTTPS demo (no purchased domain)

Compose 2.24.4+ is required for the port override. Start the optional Quick Tunnel:

```sh
docker compose -f compose.yaml -f compose.tunnel.yaml up --build -d
docker compose -f compose.yaml -f compose.tunnel.yaml logs tunnel
```

Open the printed https://….trycloudflare.com URL and its /api/healthz and /api/docs
paths. Test it from a phone on mobile data. Local access is http://localhost:8080.
The tunnel is outbound-only; no inbound router ports, DNS change, account, or
payment is needed. TLS terminates at Cloudflare; traffic travels through its
encrypted tunnel, then HTTP over the local Docker network to Caddy. This mode
does not claim Caddy issued a certificate for a custom domain.

The laptop must remain awake and online. The hostname changes on tunnel restart;
copy the new URL to any remote clients. Quick Tunnels are for development/demo,
have no uptime guarantee, and do not support SSE; the plan's polling works.
Stop with the same two `-f` flags and `down`. Do not use `down -v` if you want to
retain Caddy's certificate storage.

## Existing domain and reachable host (optional)

If you already have a free/owned domain and a host reachable on TCP 80/443,
point its A record (and AAAA only if IPv6 works) to that host. Set
SITE_ADDRESS=demo.your-domain.example and use only compose.yaml. Caddy obtains
and renews certificates automatically and redirects HTTP to HTTPS. Check:

```sh
docker compose up --build -d
docker compose logs caddy
curl --fail https://demo.your-domain.example/api/healthz
```

This requires actual DNS/host access; configuration alone is not a live HTTPS
deployment. For a stable existing domain behind NAT, a named Cloudflare Tunnel
is another option, requiring a Cloudflare account/domain configuration.

## Python checks without Docker

```sh
uv venv --python 3.12
uv pip install -r api/requirements-dev.txt
uv run --no-project python -m pytest -q
uv run --no-project python -m api.manage init-db
uv run --no-project uvicorn api.main:app --host 127.0.0.1 --port 8000
```

## Scope

Set `SECURIOT_TEST_DATABASE=1` to include real database checks after initialization
(PowerShell: `$env:SECURIOT_TEST_DATABASE='1'`). The integration test inserts rows
inside a rollback-only transaction. Ordinary tests use an explicit test double;
they do not claim live database acceptance.

Included: health/readiness, OpenAPI docs, CORS allowlist, Docker/Caddy, SPA fallback,
contract/fixtures/inventory, database schema, judge seed, JWT login and identity.
H8–12 adds ingest, sync, acknowledgement, devices, and events. Set AGENT_API_KEY
in api/.env for agent requests (X-API-Key header). Dashboard reads use Bearer JWT.
H12–16 adds command creation, policy editing, and demo storage. H16–20 adds
audit lifecycle tracking, restore controls, seeded digest history, and asynchronous
event explanations. See
contract/README.md for retry and concurrency semantics. Audit endpoints, the
React UI, and optional camera-frame relay remain later work; hardware enforcement
stays in the agent.

## Commands and policy

GET/PUT `/api/policy` and POST `/api/actions` require the judge JWT. Defaults:
learning_mode=true, protected_macs=[], and notify/block_wan/quarantine enabled.
The empty protected list contains no invented hardware MACs: configure the real
router/projector MACs before arming. The agent retains its local protected list.
PUT replaces the whole policy; omitted fields receive safe defaults, not prior
values. GET returns an ETag; pass it verbatim in If-Match to reject stale saves
with 412. Identical saves do not increase the revision.

POST `/api/actions` accepts `{action, mac}` (restore_all must omit mac). It returns
202 with the queued Command, not proof of enforcement. Supply a UUID in
Idempotency-Key and reuse it for a retry; a different payload with the same key
returns 409. Replays return the original command even if already acknowledged or
cancelled, without enqueueing it again. Without the header, each request creates
a new command. Unknown targets return 404. Containment returns 409 in learning
mode, for protected MACs, or when its ladder step is disabled. Restore and Restore
all remain available in learning mode. Device status changes only through agent
telemetry, not by clicking a dashboard action or writing an acknowledgement.

Policy changes cancel pending containment commands that are no longer allowed;
re-arming never revives them. Already-delivered commands cannot be recalled by
the API. The agent must enforce its safeguards at execution. A late acknowledgement
records the actual result even if the queue entry was cancelled meanwhile.
Migration 002 permits the internal cancelled state; run init-db before deployment.

## Audit, restore, and event explanations

GET `/api/audit` returns the newest 1000 lifecycle entries. Migration 003
backfills existing commands and adds four rows whose actor is `seeded-demo`.
POST `/api/actions` creates one `requested` row per idempotency key; `/ack`
changes it to `applied` or `failed`. Restore and Restore all are queued commands:
neither the API nor dashboard changes device state before acknowledgement.

POST `/api/audit/run` passes that history to Person C's
`ml.securiot_ml.digest.digest(history)` and expects a string or
`{summary: string}`. The current teammate file is empty, so the endpoint returns
503 until the function lands; it does not fabricate a digest.

GET `/api/events` always includes `explanation` and `explanation_status`.
Without both GEMINI_API_KEY and GEMINI_MODEL, it returns Person C's template with
status `template`. With both configured, the first read returns that template as
`pending` while a bounded worker calls Person C's `explain(event, device)` away
from the request path. Later reads return the event-ID-cached result as `ready`.
Gemini failure also caches the template, so ingestion and dashboard reads remain
available. Gemini never decides or performs containment.

After pulling these changes, run `python -m api.manage init-db` before restarting
the API, then rebuild Compose. The API requires schema migration version 3.

## Demo fallback and badge

`STORAGE_MODE` in api/.env supports `auto` (default), `postgres`, and `memory`.
In memory mode DATABASE_URL is optional. Keep JWT_SECRET, AGENT_API_KEY, and
JUDGE_PASSWORD configured; secrets are never defaulted to public demo credentials.
Auto switches on a lost database connection. It does not mask schema/SQL errors,
missing migrations, or query timeouts. A failed database write returns 503 on the
triggering request because COMMIT may have succeeded; it is never blindly replayed
into the other store. Subsequent requests use memory. Refresh storage status and
retain the same idempotency key when retrying an action.

Memory is a separate single-process SQLite database. It starts with no devices,
events, or commands, learning mode ON, and the latest policy protection/ladder
values this API process has observed (otherwise safe defaults). The agent's next
upload repopulates device snapshots. Already-delivered historical events are not
replayed automatically. Previously observed user hashes/identities are cached in
RAM, including disabled status. A cold outage permits the explicitly configured
judge credentials; PostgreSQL-only account changes cannot be checked offline.
An old JWT may require re-login after a cold restart. This is demo availability,
not a multi-user production identity fallback. Set STORAGE_MODE=postgres when
authoritative database-backed identity checks must remain mandatory.

GET `/api/storage` returns `{mode, demo_storage, persistent, badge, reason, recovery}`.
All API responses expose X-Storage-Mode and X-Demo-Storage, including errors and
304 sync responses. CORS exposes those headers and ETag. The placeholder page
polls storage status, shows a text badge, and explains temporary-data loss;
Person D should use the same endpoint/headers in the React dashboard.

Fallback is latched until restart, even if PostgreSQL recovers. This avoids
alternating between different command queues. Export needed demo data using the
existing authenticated reads before restarting; memory data is discarded, not
silently merged. Restart in auto/postgres to reconnect to Tiger Data. Inspect
pending PostgreSQL commands before reconnecting the agent; the old persistent
queue may still exist. Memory commands never migrate automatically. Limits are
1000 devices, 10000 events, and 1000 commands; exceeding them returns 503 without
silently dropping data. Run one API process/replica for auto or memory mode.
For multiple workers use postgres mode. Tests inject database failure without
stopping or altering the actual Tiger Data service.

Run platform checks with `python -m pytest -q tests`; this avoids collecting the
separate ML package before it has been installed. Enable SECURIOT_TEST_DATABASE=1
for the rollback-only real database ingest/ack tests as well.

After starting Compose, check the deployed service without creating demo data:
`python -m scripts.check_platform --url http://localhost:8080`.
Use the printed tunnel HTTPS origin instead to verify public transport.
This check parses credentials through dotenv and does not print passwords/tokens.
The broader agent/API/ML suite uses `agent/requirements-test.txt` and runs with
`python -m pytest -q tests agent/tests ml/tests`.
No Git commits are required by these instructions.

References: [Caddy automatic HTTPS](https://caddyserver.com/docs/automatic-https),
[Caddy routing patterns](https://caddyserver.com/docs/caddyfile/patterns),
[Cloudflare Quick Tunnels](https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/).
Database/auth references: [Tiger Data hypertable uniqueness](https://www.tigerdata.com/docs/build/performance-optimization/hypertables-and-unique-indexes),
[FastAPI JWT and password hashing](https://fastapi.tiangolo.com/tutorial/security/oauth2-jwt/).
