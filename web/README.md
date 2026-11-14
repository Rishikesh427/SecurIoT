# SecurIoT dashboard (`/web`)

React + Vite + Tailwind. Person D's frontend from the v3.2 plan.

```bash
cd web
npm install
npm run dev        # http://localhost:5173
```

`npm run dev` uses **mock data** by default, so it needs no agent, API or Pi. Any username and password logs in. Production builds (`npm run build`) use the real API.

## Demo in mock mode

1. Turn on **Automatic protection** (the switch at the top right of Overview).
2. In the **Demo** pill at the bottom left, click **Simulate QR attack**.
3. About 2 s later the camera "attacks": network sweep, decoy accessed, port scan. About 1.3 s after that it's isolated: the camera tile switches to "Camera isolated", an alert tone plays and the alert is read aloud, and the containment timer shows the seconds.
4. Click **View cleanup steps** (or the camera row) for the summary, risk breakdown and steps, then **Restore**. The camera rejoins after about 12 s.
5. **Cloud outage** shows the offline banner. The **Activity** tab has the audit log (with Undo), **Run audit**, and the full event list.

With protection off (learning mode), the same attack is reported as "would have" and nothing is isolated.

## Real backend

**Local, against the API on port 8000:** start the API from the repo root (`uvicorn api.main:app --port 8000`), then run the dashboard with mock mode off:

```bash
VITE_USE_MOCK=false npm run dev
```

The dev server proxies `/api/*` to `http://localhost:8000` with the prefix stripped, the same way Caddy does, so there's no CORS setup. Log in with the judge account.

**Docker (Person B's setup):** build the bundle, point Caddy at it, recreate Caddy:

```bash
cd web && npm run build          # real API at /api; nothing secret goes in the bundle
# in the repo-root .env:  WEB_BUNDLE_PATH=./web/dist
docker compose up -d --force-recreate caddy
```

**Settings** (`web/.env`, all optional):

| Variable | Default | Purpose |
|---|---|---|
| `VITE_API_URL` (or `VITE_API_BASE_URL`) | `/api` | API base |
| `VITE_USE_MOCK` | `true` in dev, `false` in builds | Force mock on or off |
| `VITE_FEED_URL` | unset | Agent's local API (e.g. `http://10.42.0.1:8787`) for the live camera feed. Unset, the camera tile follows the device status |

Never put keys in `web/.env`. Everything there ends up in the public bundle.

**Routes not built yet:** the dashboard checks once per load. Without `/policy`, the protection switch and Settings say "not available yet"; without `/actions`, Isolate/Restore are hidden; without `/audit` and `/audit/run`, the audit log and digest say so. Everything else (devices, activity, risk, containment) works from `/devices` and `/events`. A 401 signs you out.

Mock mode reads `../contract/fixtures.json` directly, so the mock data always matches the contract.

## Where things are

| Path | What |
|---|---|
| `src/types.ts` | Types mirroring `contract/schemas.json` |
| `src/mock/` | Contract fixtures plus the in-memory mock API with the scripted QR attack |
| `src/api/client.ts` | Switches between mock and real API |
| `src/lib/incident.ts` | Incidents, containment timing, template summaries, cleanup steps |
| `src/components/` | Device list, activity, camera status tile, containment timer + before/after, device sheet, settings, audit |

## Open questions for the contract

- **Explanations:** there's no Gemini route yet, so summaries are templates (the plan's fallback). If the API adds e.g. `GET /events/{id}/explanation`, wire it into `lib/incident.ts`.
- **Containment timer:** the contract has no enforcement timestamp. The dashboard reads optional `evidence.first_evidence_at` and `evidence.enforced_at` on the event that carries `actions_taken`, and otherwise estimates from event timestamps. It would help if the agent sent both.
- **Detection thresholds** and **Ignore** aren't in the contract's Policy/Action, so the dashboard doesn't offer them.
- **Isolate** sends `quarantine`; the agent applies the block + quarantine bundle.
