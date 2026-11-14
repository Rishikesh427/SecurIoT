# SecurIoT dashboard (`/web`)

React + Vite + Tailwind. Person D's frontend from the v3.2 plan.

```bash
cd web
npm install
npm run dev        # http://localhost:5173
```

By default it runs on **mock data** (`VITE_USE_MOCK=true`), so it needs no agent, API or Pi. Any username and password logs in.

## Demo in mock mode

1. Turn on **Automatic protection** (the switch at the top right of Overview).
2. In the **Demo** pill at the bottom left, click **Simulate QR attack**.
3. About 2 s later the camera "attacks": network sweep, decoy accessed, port scan. About 1.3 s after that it's isolated: the camera tile switches to "Camera isolated", an alert tone plays and the alert is read aloud, and the containment timer shows the seconds.
4. Click **View cleanup steps** (or the camera row) for the summary, risk breakdown and steps, then **Restore**. The camera rejoins after about 12 s.
5. **Cloud outage** shows the offline banner. The **Activity** tab has the audit log (with Undo), **Run audit**, and the full event list.

With protection off (learning mode), the same attack is reported as "would have" and nothing is isolated.

## Real backend

Set in `web/.env`:

```
VITE_API_BASE_URL=/api     # same-origin Caddy proxy; or http://localhost:8000, or http://10.42.0.1:8787 for the agent
VITE_USE_MOCK=false
```

The dashboard follows `/contract` (schemas.json and the route table in contract/README.md):
`POST /auth/login`, `GET /devices`, `GET /events`, `GET/PUT /policy`, `POST /actions` (`{action, mac}`), `GET /audit`, `POST /audit/run`, plus the agent's `GET /feed/{mac}/meta` for the camera tile. A 401 signs you out.

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
