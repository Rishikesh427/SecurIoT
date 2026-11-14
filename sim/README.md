# Hardware-free ingest simulation

This posts `contract/fixtures.json`, then scripted ARP-scan, target-scan, and
decoy-contact events to the real `/ingest` API. All devices/events are labelled
simulated. Actions taken remain empty; the decoy event records would-have actions.
It does not scan the network, execute the detector, change policy, enqueue commands,
or acknowledge commands. Existing simulation MAC addresses are reused; their latest
inventory reports are updated. Each run adds new event UUIDs and current timestamps.

From the repository root in PowerShell, with Docker Desktop running:

```powershell
docker compose up --build -d
py -m pip install -r sim/requirements.txt
py sim/sim.py --url http://localhost
```

The agent key is read from `api/.env`; process `AGENT_API_KEY` overrides it.
Never paste it into the frontend or command-line arguments. If using the tunnel
Compose override, pass `--url http://localhost:8080` instead.

Sign into http://localhost using the real judge account. Ensure the dashboard is
built with `VITE_MOCK_MODE=false` (the default); fixture mock mode cannot show these
uploads. Reports refresh every ten seconds. Five events are uploaded per run:
two shared fixture events and three scripted events. Memory fallback is explicitly
printed as `storage=memory` and loses the reports on API restart.

Preview without API access or dependencies:

```powershell
py sim/sim.py --dry-run
```

Use `--interval 0` for an immediate run (default is three seconds between steps).
Failed requests stop the run; it does not retry uncertain writes automatically.
Previously accepted batches remain. Rerunning creates new UUIDs and adds another
demo sequence. For a 503, inspect `/api/storage` before rerunning.

Tests: `py -m unittest discover -s sim -t . -p "test_*.py"`.
