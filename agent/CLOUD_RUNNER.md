# Agent cloud delivery and commands

Reviewed at `332f573` (November 15, 2026). [Recent changes](../docs/RECENT_CHANGES.md)
record PRs #16–20, current tests and integration gaps.

## Supported sources and server mode

`--connect` is supported with replay and live capture. Replay remains local/mock;
the normally configured API uses `Settings.load(live_only=True)` and rejects
simulated devices/events with 409, even in memory storage. Use offline replay for
local detector tests and explicitly isolated non-live test settings for simulated
HTTP integration. There is no documented environment switch to make the normal
server accept fixtures.

For the real live agent, follow [Linux setup](LINUX_ENFORCEMENT.md): configure
`SECURIOT_DISCOVERY_CONFIG`, real enforcement, `AGENT_API_KEY` and `--api-url`.
The live CLI rejects `--devices` and mock enforcement. `--arm` controls automatic
response; manual commands have separate override semantics.

HTTPS is required outside loopback. Docker's Caddy normally exposes the API at
`http://localhost/api`; direct host uvicorn uses `http://127.0.0.1:8000`.
Keys come from the environment, are not command-line arguments, and must match
the API. `agent/.env.example` is a reference, not an automatically loaded file.

## Execution and delivery

- Fetch authoritative policy before packet processing. Successful live cloud cycles
  are scheduled every 0.5 seconds; error backoff is bounded at 30 seconds.
- Presence transitions request an immediate upload. Unchanged device digest plus
  unchanged outbox cursor can skip ingest; sync remains a heartbeat.
- Runtime mutations are single-writer. Capture enqueues on another thread with a
  bounded buffer; overload/gaps can invalidate traffic coverage/baseline windows.
- `wire.py` exports current contract fields, including identity/firmware,
  `snapshot_at`, real/simulation provenance, and offline presentation. Restriction
  status wins over offline. The live path strips retired simulated pending records.
- Inferred type/vendor fields rejected by a schema can downgrade to unknown before
  retry validation. Other invalid data is retained/reported, not silently accepted.
- Each pending ingest batch is journaled exactly. Accepted responses advance the
  outbox cursor; UUIDs/ts are immutable on retries. Events remain in the local audit.

The API's migration-6 storage upsert compares `snapshot_at` (falling back to
`last_seen`); last packet time no longer has to change just to publish presence.
PostgreSQL event ingestion batches UUID checks/inserts to avoid round trips per
event under the storage lock. These changes reduce API stalls, but are not a
throughput or containment latency guarantee.

## Manual actions

Dashboard JWT requests create command/audit records and use UUID idempotency keys.
`POST /actions` returns 202 when queued. `?wait=true` waits up to ten seconds and
can return 200 with a terminal result, or pending after the wait. The browser uses
a longer request timeout; loss of a response leaves the outcome uncertain.

CloudLoop fetches current policy, records intent, applies a command with
`manual=True`, freezes its Ack and retries delivery without repeating the UUID.
Already-restricted requests can be acknowledged applied. A crash-interrupted
intent becomes failed/uncertain for review instead of an exactly-once claim.
Restore does not extend grace on acknowledgement retry.

Manual containment overrides automatic learning/arming, warmup, cooldown and
Restore grace. Explicit controller/cloud protection and disabled steps still
apply. A default guest's automatic protection differs from explicit manual
protection. Restore/Restore all are recovery operations; switching learning mode
does not undo existing restrictions. A policy change can cancel queued unsafe
containment, so receiving a request does not guarantee execution.

`DirectControl` is present as an authenticated loopback listener class but is not
constructed/drained by the current live runner; the API does not dispatch through
`SECURIOT_ROUTER_URL`. See [Pi controls status](../docs/PI_DIRECT_CONTROL.md).

## State, tests and optional adapter factory

Use one process per state directory. `cloud.json` is bound to the API identity;
use a different directory when changing servers. Never delete it just to retry
an action. `presence.json`, discovery, routine and enforcement journals have
separate responsibilities; see [agent overview](README.md).

```bash
agent/.venv/bin/python -m pytest agent/tests/test_cloud.py agent/tests/test_linux_enforcement.py agent/tests/test_presence.py -q
```

Current suite failures are listed in [the audit](../docs/RECENT_CHANGES.md#verification-and-known-gaps).
The historical `tools/smoke_stack.py` sends simulated replay telemetry and must
be assessed against live-only API settings before reusing it; an earlier pass is
not a current deployment verification. No external database or provider call is
needed for the local unit/API tests.

Replay-only `--detector-factory module:factory` remains available with `--connect`.
The factory accepts `clock` and `protected_macs` and returns `observe(Observation)`
and `assess_device(Device)` methods. The standard built-in trained adapter is
documented in [MODEL_HANDOFF.md](MODEL_HANDOFF.md); custom adapters must preserve
feature units, cadence, provenance and deliberate containment eligibility.
