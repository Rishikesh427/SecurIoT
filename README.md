# 🛡️ SecurIoT

**Your smart TV is spying on you. Your smart plug is a backdoor. And you can't patch either one.**

A 2026 Bitdefender/NETGEAR study of 10.4 million homes found that smart TVs, smart plugs, and NAS devices make up **67.1% of all observed home vulnerabilities**. Owners can't fix the firmware, and most never see the threat coming.

**SecurIoT fixes the one place you can: the network.**

## What if your router could think?

- **Sees everything.** Every phone, speaker, projector, and plug is discovered and fingerprinted within seconds of joining.
- **Knows what's normal.** It learns each device's habits (destinations, data volume, active hours) and spots the moment one goes rogue.
- **Explains in plain English.** Gemini turns "anomaly score 0.91" into "Your phone just scanned 40 devices in 5 seconds. Here's why that matters."
- **Acts before you wake up.** It escalates automatically: notify, block internet, quarantine, then cut the device off entirely.
- **Never locks you out.** Learning mode, a critical-device safeguard, and a one-click undo on every action.

## Watch it work (live demo)

1. Everything on the dashboard is green.
2. We attack from a phone: a network scan plus a beacon to a suspicious domain.
3. **In seconds**, SecurIoT flags it, Gemini explains it, and the device is walled off.
4. The Bluetooth speaker goes silent, physical proof that containment worked.
5. One click on **Restore**, and everything is back.

Time to containment is on screen. No guesswork.

## Why it wins

| Others | SecurIoT |
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
- **Reasoning:** Gemini classifies devices and writes the risk analysis, with a rules-only fallback so it never goes blind.
- **Platform:** **Vultr** hosting, **Tiger Data** time-series, **GoDaddy Registry** demo domain, **Entire** repo workflow.

```
Agent → /ingest → DB → Scorer + Baseline → Gemini
      → Response engine → /commands → Agent enforces → Audit log → Dashboard
```

## Try it

```bash
cd ml && pip install -r requirements.txt && pytest -q    # scorer tests
cd api && uvicorn main:app --reload                       # backend
cd web && npm install && npm run dev                      # dashboard
sudo python agent/agent.py --api $API_URL --key $AGENT_API_KEY
```

Set `DATABASE_URL`, `GEMINI_API_KEY`, `JWT_SECRET`, and `AGENT_API_KEY` in `.env`.

## The vision

Every home router should defend like an enterprise firewall, no security degree required. Next up: a community threat feed, Matter/Thread checks, and tamper-proof audit logs on Solana.

**SecurIoT: security for the devices you can't patch.**

*Only test on devices and networks you own.*
