# 🛡️ CasaWarden

## Project name and compatibility

**CasaWarden is the new name of the project previously called SecurIoT.** Use
CasaWarden in documentation, presentations, and new project descriptions.

Existing internal identifiers intentionally retain the legacy name to keep
imports, deployment configuration, authentication, persisted data, and recovery
behavior compatible. Examples include the `securiot_agent` and `securiot_ml`
Python packages, the `securiot-agent` command, `SECURIOT_*` environment variables,
the PostgreSQL schema and Docker Compose project named `securiot`, JWT
issuer/audience defaults, browser storage keys, and the `securiot_guard` firewall
tables and ownership markers. Configuration/state paths such as `/etc/securiot`
and `/var/lib/securiot` also keep their existing names.

Copy documented commands and identifiers exactly as written. These names belong
to CasaWarden's existing implementation; they do not indicate a separate product.
Some current UI labels, API metadata, schemas, and logs may still display
SecurIoT. This documentation rename leaves those implementation names in place;
renaming them would require a coordinated compatibility and migration change.

**Your smart TV is spying on you. Your smart plug is a backdoor. And you can't patch either one.**

A 2026 Bitdefender/NETGEAR study of 10.4 million homes found that smart TVs, smart plugs, and NAS devices make up **67.1% of all observed home vulnerabilities**. Owners can't fix the firmware, and most never see the threat coming.

**So we asked ourselves: what's the one place we can fix? The network.**

## What if your router could think?

- **Sees everything.** Every phone, speaker, projector, and plug is discovered and fingerprinted within seconds of joining.
- **Knows what's normal.** It learns each device's habits (destinations, data volume, active hours) and spots the moment one goes rogue.
- **Explains in plain English.** Gemini turns "anomaly score 0.91" into "Your phone just scanned 40 devices in 5 seconds. Here's why that matters."
- **Acts before you wake up.** It escalates automatically: notify, block internet, quarantine, then cut the device off entirely.
- **Never locks you out.** Learning mode, a critical-device safeguard, and a one-click undo on every action.

## Watch it work (live demo)

1. Everything on the dashboard is green.
2. We attack from a phone: a network scan plus a beacon to a suspicious domain.
3. **In seconds**, CasaWarden flags it, Gemini explains it, and the device is walled off.
4. The Bluetooth speaker goes silent, physical proof that containment worked.
5. One click on **Restore**, and everything is back.

Time to containment is on screen. No guesswork.

## Why it wins

| Others | CasaWarden |
|---|---|
| Alert you, then wait | **Acts automatically, safely** |
| Need vendor firmware patches | **Protects devices that can never be patched** |
| Show jargon and logs | **Gemini explains in human language** |
| One-size-fits-all rules | **Per-device behavioral baselines** |
| Black-box actions | **Audit log with undo for everything** |

## Under the hood

| Folder | What it does |
|---|---|
| `/agent` | Router laptop: discovers devices, collects flows, enforces `nftables` and Bluetooth rules |
| `/api` | FastAPI: auth, ingest, response ladder, audit log |
| `/ml` | Risk scorer, baselining (z-score + Isolation Forest), Gemini prompts |
| `/web` | React dashboard: device grid, live feed, explanations, one-click actions |

- **Risk score 0-100:** known exploited CVEs (+30), end-of-life firmware (+20), exposed ports (+15), cloud-only (+10), default credentials (+25), live anomalies (up to +40).
- **Advice:** Gemini suggests types for unknown devices, explains risk, offers hardening steps,
  ranks fixes, and answers per-device questions. Its displayed score adjustment is capped
  at ±10; rules and detectors drive enforcement. Advice falls back to local rules offline.
- **Platform:** local Docker Compose (FastAPI + Caddy), with an optional free Cloudflare Quick Tunnel for public HTTPS. Tiger Data tables and JWT judge login are implemented.

```
Agent detectors → Local response ladder → Enforcement
Agent telemetry → API /ingest → DB → Dashboard
                                → Gemini advice → Dashboard (display adjustment only)
Dashboard controls → API commands → Agent checks and enforces → Audit
```

## Try it

For the implemented Person B H1–20 platform, login, telemetry, controls, audit,
asynchronous event explanations, and demo fallback, follow [platform setup](deploy/README.md).
Shared schemas, demo fixtures, and hardware placeholders live in [contract](contract/README.md).

The [React and TypeScript dashboard](web/README.md) provides login, searchable
device inventory, an event feed, and storage status. Run
`docker compose up --build -d` and open http://localhost. Caddy builds the frontend
bundle automatically; no frontend credentials or agent keys are required.
The commands below describe later tracks and are not all implemented yet.

```bash
cd ml && pip install -r requirements.txt && pytest -q    # scorer tests
uvicorn api.main:app --reload                             # backend, from repository root
cd web && npm install && npm run dev                      # dashboard
sudo python agent/agent.py --api $API_URL --key $AGENT_API_KEY
```

Set `DATABASE_URL`, `GEMINI_API_KEY`, `JWT_SECRET`, and `AGENT_API_KEY` in `.env`.
Set `GEMINI_MODEL` too. Rebuild with `docker compose up -d --build`, then open a
device for AI advice and chat. **Prioritize devices** suggests what to fix first.
See [advisor setup](deploy/README.md#gemini-advisor-three-steps) for configuration
and fallback behavior. No schema migration is needed for this feature.

## The Mission

Every home router should defend like an enterprise firewall, no security degree required.

**CasaWarden: security for the devices you can't patch.**

*Only test on devices and networks you own.*
