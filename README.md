# SecurIoT
IoT Sentinel

Your smart TV is spying on you. Your smart plug is a backdoor. And you can’t patch either one.

A 2026 Bitdefender/NETGEAR study of 10.4 million homes found that smart TVs, smart plugs, and NAS devices make up 67.1% of all observed home vulnerabilities. The owners can’t fix the firmware, and most never see the threat coming.

IoT Sentinel fixes the one place you can: the network.

What if your router could think?

Sentinel sits at the router and does what no consumer product does today:

Sees everything. Every phone, speaker, projector, and plug is discovered and fingerprinted within seconds of joining.
Knows what’s normal. It learns each device’s habits (destinations, data volume, active hours) and spots the moment one goes rogue.
Explains in plain English. Gemini turns “anomaly score 0.91” into “Your phone just scanned 40 devices in 5 seconds. Here’s why that matters.”
Acts before you wake up. It escalates automatically: notify, block internet, quarantine, then cut the device off entirely.
Never locks you out. Learning mode, a critical-device safeguard, and a one-click undo on every action.
Watch it work (the live demo)
Everything on the dashboard is green.
We run an attack from a phone: a network scan plus a beacon to a suspicious domain.
In seconds, Sentinel flags it, Gemini explains it, and the device is walled off.
The Bluetooth speaker goes silent, a physical proof that containment worked.
One click on Restore, and everything is back.

Time to containment is on screen. No guesswork.

Why it wins
Others	IoT Sentinel
Alert you, then wait	Acts automatically, safely
Need vendor firmware patches	Protects devices that can never be patched
Show jargon and logs	Gemini explains in human language
One-size-fits-all rules	Per-device behavioral baselines
Black-box actions	Audit log with undo for everything
Under the hood
Risk score 0-100: known exploited CVEs, end-of-life firmware, exposed ports, default credentials, and live anomalies.
Detection: z-score baselines plus an Isolation Forest.
Reasoning: Gemini classifies devices and writes the risk analysis, with a rules-only fallback so it never goes blind.
Enforcement: real nftables rules and Bluetooth control on a laptop acting as the router.
Platform: FastAPI and React on Vultr, time-series data in Tiger Data, our demo domain from GoDaddy Registry, and the repo workflow on Entire.
Try it
bash
cd ml && pip install -r requirements.txt && pytest -q   # scorer
cd api && uvicorn main:app --reload                      # backend
cd web && npm install && npm run dev                     # dashboard
sudo python agent/agent.py --api $API_URL --key $AGENT_API_KEY

Set DATABASE_URL, GEMINI_API_KEY, JWT_SECRET, and AGENT_API_KEY in .env. Demo login is on the slide.

The vision

Every home router should defend like an enterprise firewall, with no security degree required. Next up: a community threat feed, Matter/Thread checks, and tamper-proof audit logs on Solana.

IoT Sentinel: security for the devices you can’t patch.

Only test on devices and networks you own.
