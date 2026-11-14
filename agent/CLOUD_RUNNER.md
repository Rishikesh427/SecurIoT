# Agent cloud loop

This is an offline packet-replay runner with mock enforcement. It uses C's arrived trained scan model plus
rules/scorer and B's existing ingest/sync/ack contract. It can upload results,
process queued Restore commands, and keep polling after replay reaches EOF.
It does not provide a live sniffer, firewall backend, dashboard, or trained model training.

## Setup and run

From the repository root:

```bash
agent/.venv/bin/python -m pip install -r agent/requirements-test.txt
export SECURIOT_API_URL=http://127.0.0.1:8000
export AGENT_API_KEY='replace-with-the-key-configured-on-your-api'
agent/.venv/bin/python agent/agent.py --replay agent/fixtures/arp_scan.pcap --connect --arm
```

Start B's API separately using that track's instructions and database configuration.
The runner sends `X-API-Key`. HTTPS is required for remote APIs; plain HTTP is
accepted only for loopback development. Redirects are not followed. Keys are
read from the environment, never printed or written to the command journal.
`agent/.env.example` is a reference, not an automatically executed/loaded file.

The runner fetches policy before processing packets and polls about every two
seconds while replaying and after EOF. Once EOF is reached it waits for commands;
it does not loop/replay the attack automatically. Ctrl-C stops it. `--once`
processes the capture, performs one final cloud cycle, then exits; incomplete
cloud work gives a nonzero exit and remains on disk. To start an independent run,
use a fresh `--state-dir`. Use one process per state directory.

`--arm` gives permission for cloud policy to enable mock actions. Without it,
cloud policy cannot turn off learning mode. Cloud learning mode and locally
protected MACs remain authoritative safeguards. Per-step ladder toggles are
honored; the default automatic action is quarantine. The full V5 block+quarantine
hardware bundle is still a future enforcement integration.

## Delivery and recovery

- All local audit events remain in JSONL. Only event kinds supported by the shared
  ingest contract are exported. Audit-only/unsupported kinds stay local.
- Conversion maps statuses, timestamps, confidence vocabulary, and anomaly ratios
  to the shared schema. Every upload is validated before sending. Payloads are
  explicitly marked as simulated/mock.
- `cloud.json` freezes each pending payload, including UUIDs and timestamps, before
  upload. A lost response causes the exact same payload to be retried after restart.
- A cursor advances only after a valid ingest response. Acknowledged events remain
  in the local audit file; a failed response never discards them.
- Each command UUID/content hash is journaled before execution, then its exact ack
  is saved. Lost acknowledgement responses do not repeat Restore or extend grace.
- A crash with an unfinished command records an uncertain failure on restart rather
  than risking repeated action. This is not a claim of transactional exactly-once
  enforcement. A different command payload reusing an old UUID is rejected.
- Journals are bound to the API URL. Use another state directory when changing APIs.
- API errors are bounded by timeouts and retained for retry. This single-threaded
  offline harness can pause packet-file processing during HTTP calls; live packet
  capture must be decoupled before claiming real-time containment under outages.

Successful mock actions update the simulated device snapshot timestamp, allowing
B's newer-snapshot upsert to display Restore. Real hardware should distinguish
last observed activity and state revision when that contract is extended.

## Repeat the tests

```bash
agent/.venv/bin/python -m pytest agent/tests ml/tests -q
```

Cloud tests exercise B's real FastAPI routes/validators with a test database and
also exercise the actual loopback HTTP client/runner. They verify reconnect,
response loss, deduplication, commands, acknowledgements, malformed policies,
authentication, and local safeguards. They do not verify deployed Vultr/Tiger Data.
B's `/actions` dashboard command-creation endpoint is a separate dependency;
tests seed its queue directly rather than pretend a dashboard click exists.

## Trained model handoff

The arrived bundle is connected by the built-in adapter. See [MODEL_HANDOFF.md](MODEL_HANDOFF.md) for verified feature/timing compatibility and evaluation limits. `--detector-factory package.module:factory` explicitly
loads an installed adapter, with no silent fallback if loading fails.

Factory signature:

```python
def factory(*, clock, protected_macs):
    return Adapter(...)  # loads C's actual weights + saved preprocessing
```

The adapter must implement `observe(Observation) -> Finding | None` and
`assess_device(Device) -> assessment_dict`. It must use the actual training feature
order/units/windowing and return a deliberate `containment_allowed` decision.
Assessments need type, eol, cloud_only, risk, band, confidence, and reasons; inspect
`ml_adapter.py`/`wire.py` for current local conventions. Normalized anomaly evidence
is 0–1 locally and 0–40 points on the wire. Optional `anomaly` per-MAC state supplies
that conversion. Training/prediction confidence must be calibrated before it is
presented as a probability. The built-in adapter now requires the model by default. Use `--model-mode rules`
for deliberate rule regressions; a custom factory remains an alternative integration interface.


## Model + Docker smoke test

The arrived artifact is the default required model. Install the full
`agent/requirements-test.txt` set, then run:

```bash
agent/.venv/bin/python agent/tools/smoke_stack.py
```

This builds the repository's actual API and React/Caddy images in a separate
Compose project, uses ephemeral credentials/SQLite memory storage, verifies
model predictions, upload, authenticated Restore, acknowledgement, and retry
idempotency, then removes only its own containers/volumes. It does not read the
configured database credentials into containers or change your saved `.env`.
Build images/cache remain available for later runs. See MODEL_HANDOFF.md for
training provenance, cadence compatibility, and remaining hardware tests.
