# CasaWarden dashboard (`/web`)

> **Naming:** CasaWarden was previously called SecurIoT. The `securiot-web`
> package name, browser storage keys, and existing UI/API labels may still use
> the legacy name. They remain unchanged for compatibility with the current
> implementation. See the
> [project naming note](../README.md#project-name-and-compatibility).

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

**Device joins** adds a guest laptop so you can see a new device slide in. Switch **Devices** to **Map** for the network view (router in the middle, Cytoscape.js; loaded only when opened).

## How the Overview is organized

1. **Am I okay?** One status banner: green "You're protected", amber "N things need attention", red when something is under attack or cut off.
2. **What's wrong?** "What needs attention", most urgent first. Each item has a severity (Critical / High / Medium / Low, each with its own color, icon and label) and a **Fix** button.
3. **What do I do?** Fix opens plain steps, one main action (turn on protection, isolate, restore) and "I've done this". Technical terms only appear under "Technical details".
4. Activity shows a plain summary per event; click one to see its raw log entry.

## Real backend

**Local, against the API on port 8000:** start the API from the repo root (`uvicorn api.main:app --port 8000`), then run the dashboard with mock mode off:

```bash
VITE_USE_MOCK=false npm run dev
```

The dev server proxies `/api/*` to `http://localhost:8000` with the prefix stripped, the same way Caddy does, so there's no CORS setup. Log in with the judge account.

**Docker:** `compose.yaml` builds this dashboard with `web/Dockerfile` and serves it with Caddy, so from the repo root:

```bash
docker compose up --build -d     # dashboard at http://localhost, API at /api
```

Build settings come from the root `.env` (`VITE_API_URL`, default `/api`; `VITE_MOCK_MODE`, default `false`). After changing the dashboard, rebuild with `docker compose up --build -d caddy`.

**Settings** (`web/.env`, all optional):

| Variable | Default | Purpose |
|---|---|---|
| `VITE_API_URL` (or `VITE_API_BASE_URL`) | `/api` | API base |
| `VITE_USE_MOCK` or `VITE_MOCK_MODE` | `true` in dev, `false` in builds | Force mock on or off |
| `VITE_FEED_URL` | unset | Agent's local API (e.g. `http://10.42.0.1:8787`) for the live camera feed. Unset, the camera tile follows the device status |

Never put keys in `web/.env`. Everything there ends up in the public bundle.

The header shows where the API keeps data (`GET /storage`): **Tiger Data**, or **Demo storage** when the API fell back to temporary in-memory storage.

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

## Manual isolation and restore

Open a device to Quarantine it or Restore access, without requiring a detector
alert. Settings must enable protection, and the live agent must be locally armed.
Protected devices remain exempt. The dashboard shows queued commands until an
agent acknowledgement; queueing does not optimistically change device status.
Manual containment bypasses automatic timing delays; Restore provides a minimum
60-second automatic grace period. The Linux backend and run commands are in
[agent/LINUX_ENFORCEMENT.md](../agent/LINUX_ENFORCEMENT.md).

Run `npm test` for component/action tests and `npm run build` for type checking
and a production build. The firewall's actual packet tests run separately in
Docker; physical hostapd disconnect/reconnect acceptance requires the Linux AP.
