# CasaWarden dashboard

Reviewed at `332f573` (November 15, 2026). See [recent changes and current
verification](../docs/RECENT_CHANGES.md). Legacy package/browser keys remain
unchanged; see the [naming note](../README.md#project-name-and-compatibility).

## Start

From the repository root:

```bash
docker compose up --build -d
```

Open http://localhost and sign in with an existing account. Compose runs a
mounted-source Vite development server behind Caddy; API routes share `/api`.
The web service runs `npm ci` on startup to refresh its dependency volume.
Source edits hot reload; recreate/rebuild for Dockerfile/environment changes.

For a host-based Vite server:

```bash
cd web
npm ci
npm run dev
```

Open http://localhost:5173. The client is **live API only** (`USE_MOCK=false` in
`src/api/client.ts`); neither dev mode nor `VITE_USE_MOCK`/`VITE_MOCK_MODE` enables
the old simulation. An API and real credentials are required. Fixture/mock modules
remain test helpers. Registration UI exists, but `/auth/signup` is not registered
in this revision; an invitation code does not currently enable signup.

## Navigation

- **Home:** device map, bandwidth from reported byte counters, and mutually
  exclusive Safe / Caution / Danger counts. Unknown facts do not prove safety.
- **Activity:** heatmap, searchable/filterable recorded events, Older Devices,
  Run Audit and an audit-log modal. Disconnected devices leave Home with a
  reduced-motion-aware animation and appear under Older Devices; restricted
  devices remain visible on Home. A returning client reappears when reported.
- **Prevention:** device review, prioritized issues and fix workflows.
- **Device detail:** measured/reported facts, inferred identity, risk breakdown,
  selected traffic, evidence, advisor chat/research and manual access controls.
- **Settings:** gear beside the theme control; policy/protected devices.
  Theme controls, optional sound/read-aloud and tutorial affordances are UI
  features, not detection or connectivity evidence.

Home counts exclude `offline` devices. Caution includes medium risk or a device
issue; Danger includes restriction/high risk/critical issues. These groups count
devices once each rather than adding every alert.

## Controls and outcomes

Warn calls `POST /devices/{mac}/warn` and records an informational warning; it
does not block traffic. Block Internet sends `block_wan`; Quarantine sends
`quarantine`; Restore access sends `restore`. Arm controls automatic protection.
Manual containment can work while automatic learning mode is on, bypassing
startup/cooldown/restore-grace timers; explicit protection and enabled steps
still apply. Locally configured controller protection is exposed through
`identification.manual_protected` when available.

The client sends a UUID Idempotency-Key to `/actions?wait=true`. The API queues
execution and waits up to ten seconds for a reported outcome. A returned pending
result or timeout is not proof of failure or success; audit refresh can reconcile
it. Restore may be requested while another action is pending. Successful Restore
permits reconnection and starts at least 60 seconds of automatic response grace.
The current tracked integration does not dispatch through the direct Pi listener;
see [Pi control status](../docs/PI_DIRECT_CONTROL.md).

Dashboard refresh prefers authenticated `GET /dashboard` (devices, events, audit,
policy, agent connection indication), with separate-route fallback for older
servers. `usePoll` avoids overlapping calls. API connectivity, a recent agent
`/sync`, and successful enforcement are separate facts. `/diagnostics` provides
process-local agent timings and Gemini usage/failure details.

## AI and audit

Device explanations/advice and public research are server-side. Public research
can cite vendor documentation; it does not verify the installed firmware/current
password or update risk/protection facts. Failure/budget exhaustion falls back to
rules and displays a reason. API credentials and Gemini keys never belong in
`VITE_*` values.

Run Audit returns a deterministic `summary` plus three consumer `bullets` from
recorded history. Open Audit Log shows requested, applied (reported), failed and
would-have outcomes. Simulator/seeded history is distinguished. Applied outcomes
are agent reports, not independent physical verification.

## Configuration and checks

| Variable | Current behavior |
| --- | --- |
| `VITE_API_URL` / `VITE_API_BASE_URL` | API base; default `/api` |
| `VITE_PROXY_TARGET` | Vite proxy target; default localhost:8000, Compose uses api:8000 |
| `VITE_FEED_URL` | Optional external agent-feed base; no feed server is implemented here |
| `VITE_USE_MOCK` / `VITE_MOCK_MODE` | Legacy settings; do not enable runtime fixtures |

```bash
npm test
npm run typecheck
npm run build
```

Current build/test results are in [the audit](../docs/RECENT_CHANGES.md#verification-and-known-gaps).
PR #20 restores the Landing companion export, improves map position stability,
and adds time-axis labels/exact hover ranges to Activity. The older mock-demo
walkthrough is still not a runtime feature.
