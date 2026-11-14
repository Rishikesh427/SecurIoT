# Person B: hours 1–4

This setup uses no paid hosting or provider accounts. FastAPI runs in one
container; Caddy serves a static bundle and proxies the API in another.
Docker Engine + Compose on Linux are suitable; on Windows use Docker Desktop
with Linux containers (subject to its license). No Vultr dependency.

## Local start

From the repository root, copy `.env.example` to `.env` if it does not already
exist, then:

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

The API image copies only its source and requirements. It runs as a non-root user,
has a healthcheck, and does not publish port 8000. H1–4 does not read api/.env or
connect to Tiger Data/Gemini. Existing secret files are preserved. Later work must
explicitly wire only needed backend secrets into Compose, never the web build.

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
uv run --no-project uvicorn main:app --app-dir api --host 127.0.0.1 --port 8000
```

## Scope

Included: health endpoint, OpenAPI docs, CORS allowlist, Docker/Caddy scaffolding,
SPA fallback, contract/schema/fixtures/device inventory. Auth, database, ingest,
commands, scoring, enforcement, and React UI are subsequent tracks/milestones.
No Git commits are required by these instructions.

References: [Caddy automatic HTTPS](https://caddyserver.com/docs/automatic-https),
[Caddy routing patterns](https://caddyserver.com/docs/caddyfile/patterns),
[Cloudflare Quick Tunnels](https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/).
