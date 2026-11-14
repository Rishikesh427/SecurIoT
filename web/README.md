# React dashboard

React and TypeScript implement login, inventory, event feed, and storage status.
Tokens stay in memory; reloading signs out. No agent key is shipped to the browser.

From the repository root, run `docker compose up --build -d` and open
http://localhost. Caddy builds and serves the React bundle. `/dashboard.html`
also resolves to the app through the existing SPA fallback.

For frontend development, run `npm.cmd ci --prefix web`, then
`npm.cmd run dev --prefix web`. Open the URL Vite prints; its `/api` proxy
uses the Docker stack at http://localhost.

Run `npm.cmd run build --prefix web` for TypeScript checks and the production
bundle, and `npm.cmd test --prefix web` for API-client tests.

Policy and restore controls are a subsequent increment.

## Offline fixture demo

In PowerShell, from the repository root:

```powershell
$env:VITE_MOCK_MODE = 'true'
npm.cmd run dev --prefix web
```

Open the Vite URL and sign in with `demo` / `demo`. This is an explicitly
labelled, read-only fixture demo using `contract/fixtures.json`. It makes no
API requests and does not need Docker, Tiger Data, or hardware. It is separate
from the backend's automatic in-memory database fallback.

To return to the real API, stop Vite with Ctrl+C, then:

```powershell
$env:VITE_MOCK_MODE = 'false'
$env:VITE_API_URL = '/api'
npm.cmd run dev --prefix web
```

`VITE_API_URL` includes the API prefix, for example `https://your-host/api`.
Trailing slashes are normalized. `/api` uses the Vite proxy in development and
Caddy in production. A different origin must be allowed by API `CORS_ORIGINS`.
Both settings are public build-time configuration; never put secrets in VITE variables.
For Docker set these variables in the root `.env` and rebuild Caddy with
`docker compose up --build -d caddy`. For Vite, `web/.env.local` is also supported.

Tailwind's Vite plugin generates utility styles; existing CSS preserves the
dashboard layout. Tailwind utilities style the mock-mode notices. Preflight is
omitted to avoid resetting the existing table and form styling.
