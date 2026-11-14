# Person B: hours 1–8

The API/web hosting runs locally, without a paid hosting service. FastAPI runs in one
container; Caddy serves a static bundle and proxies the API in another.
Docker Engine + Compose on Linux are suitable; on Windows use Docker Desktop
with Linux containers (subject to its license). No Vultr dependency.

## Local start

From the repository root, copy `.env.example` to `.env` and `api/.env.example` to
`api/.env` only if those files do not already exist. Configure the database and
judge settings described below, initialize the schema, then:

```sh
docker compose up --build -d
curl --fail http://localhost/api/healthz
```

Open http://localhost and http://localhost/api/docs. The initial page is an
explicit placeholder, not Person D's dashboard. Once the Vite project exists,
build it with VITE_API_URL=/api (VITE_API_BASE_URL is also provided for compatibility),
set WEB_BUNDLE_PATH=./web/dist in the root .env, and recreate Caddy:

```sh
docker compose up -d --force-recreate caddy
```

The API image copies only source, migrations, and requirements. It runs as a
non-root user, has a process healthcheck, and does not publish port 8000. Compose
injects `api/.env` into the API container only; no secrets enter the image or web
bundle. `/api/healthz` is liveness; `/api/readyz` also checks database initialization.
Database outages return 503 for readiness/auth and do not masquerade as a demo store.

## Tiger Data and the judge login

Use your existing Tiger Data connection in DATABASE_URL, preserving its TLS
settings (`sslmode=require` or stronger). This setup does not provision a paid
database or assume a free trial lasts forever. The H4–8 task requires an existing
PostgreSQL database with TimescaleDB; automatic SQLite fallback is later work.

Required settings in ignored `api/.env`:

- DATABASE_URL: the PostgreSQL connection URI; URL-encode special password characters.
- JWT_SECRET: a random secret of at least 32 characters; never a VITE_* variable.
- JUDGE_USERNAME: `judge` by default.
- JUDGE_PASSWORD: a random password of at least 16 characters, used only for seeding.
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

Login sends JSON to POST `/api/auth/login`:

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
Ingest, sync, commands, audit endpoints, scoring, enforcement, and React UI are later work.
No Git commits are required by these instructions.

References: [Caddy automatic HTTPS](https://caddyserver.com/docs/automatic-https),
[Caddy routing patterns](https://caddyserver.com/docs/caddyfile/patterns),
[Cloudflare Quick Tunnels](https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/).
Database/auth references: [Tiger Data hypertable uniqueness](https://www.tigerdata.com/docs/build/performance-optimization/hypertables-and-unique-indexes),
[FastAPI JWT and password hashing](https://fastapi.tiangolo.com/tutorial/security/oauth2-jwt/).
