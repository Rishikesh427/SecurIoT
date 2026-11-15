# CasaWarden agent

Reviewed at `332f573` on November 15, 2026. Legacy `securiot_*` package names,
commands, environment variables and state paths remain unchanged. See the
[repository audit](../docs/RECENT_CHANGES.md) for PRs #16–20 and current failures.

## Modes and installation

```bash
python3 -m venv agent/.venv
agent/.venv/bin/python -m pip install -e 'agent[cloud,replay,discovery]' -e ./ml -r ml/requirements-model.txt
agent/.venv/bin/python agent/agent.py --help
```

| Mode | Current behavior |
| --- | --- |
| `--simulate` | Scripted summary observations, mock enforcement |
| `--replay FILE` | Scapy file decoding, configured simulated inventory, mock enforcement |
| `--live IFACE` | Real Linux enforcement plus required live discovery; rejects `--devices` and mock enforcement |
| `--panic` | After stopping the live agent, recover owned Linux restrictions from its journal |

For local synthetic examples:

```bash
agent/.venv/bin/python agent/agent.py --simulate
agent/.venv/bin/python agent/agent.py --replay agent/fixtures/scan.pcap --model-mode rules
agent/.venv/bin/python agent/agent.py --replay agent/fixtures/arp_scan.pcap --arm
```

`--arm` permits automatic actions; without it automatic findings remain in learning
mode. Replay cannot select Linux enforcement. `--model-mode required` is default;
`auto` explicitly reports fallback and `rules` disables trained predictions.
Generated fixtures and explicit preview detection do not establish field accuracy.

## Real live operation

Use [LINUX_ENFORCEMENT.md](LINUX_ENFORCEMENT.md) for the complete command and AP
requirements. Required configuration includes `SECURIOT_REAL_ENFORCEMENT=yes`,
`SECURIOT_DISCOVERY_CONFIG`, `--enforcement linux`, and `--enforcement-config`.
The CLI starts live inventory from discovery rather than a fixture device file.
Both hostapd and NetworkManager/nl80211 controls are supported; nl80211 uses
station removal/upkeep rather than an admission deny list.
`--connect` also requires `AGENT_API_KEY` and an API URL; non-loopback URLs require
HTTPS. The current normally loaded API rejects simulated telemetry, so offline
replay upload needs an explicitly isolated test API rather than production.

Discovery accepts source MAC/IPs, DHCP/neighbor hints and AP station observations
within the configured IPv4 subnet, up to 20 clients. `netaddr` supplies an offline
OUI registry. Names/vendor/type are inference, not authenticated identity. Only
observed server-side SYN-ACK ports become listening-service hints; destination
ports a client probes are not services hosted by that client. The example
`protect_guests=false` makes ordinary discovered guests actionable; controller
and cloud/manual protection remain separate safeguards.

Presence uses `iw event` plus AP station polling. Announced leave uses 3 seconds
of grace and silent absence 15 seconds after observation. Packets/association can
bring a client back; unknown station state cannot prove departure. Changes request
an immediate cloud upload. `last_seen` is reported activity time (including initial quiet association) while
`snapshot_at` orders status/identity changes. Offline is a wire/display status,
not a saved enforcement restriction; quarantine/WAN block takes precedence.

## Detection and assessment

The collector passes packet deltas to C's rules and outgoing frames to the shared
trained feature window. The six-feature scan classifier predicts once per observed
second. Model-only scan warnings and calibrated volume deviations are advisory.
Strong multi-host ARP/decoy rules can request containment subject to policy.

`Routine` calibrates explicitly from 30 clean complete ten-second windows in
learning mode, persists baselines, and expires behavioral risk after 300 seconds.
It does not learn a complete destination/time-of-day profile. Calibration commands
are host-local; see `python -m securiot_agent.routine --help`.

[MODEL_HANDOFF.md](MODEL_HANDOFF.md) describes feature gates and historical dataset
evaluation. [THREAT_COVERAGE.md](THREAT_COVERAGE.md) distinguishes reported,
inferred, simulated and candidate vulnerability evidence. Unknown firmware or
credentials are not filled in from a guessed vendor/type or Gemini research.

## Actions and recovery

Automatic response respects local/cloud learning mode, protected devices, enabled
steps, at least 30 seconds warmup, 10 seconds cooldown and 60 seconds Restore grace.
Manual API commands bypass automatic learning/arming and timing checks. Explicitly
protected controllers/targets and disabled steps are still guarded; default guest
automatic protection may be overridden by a manual action.

Warn is API audit-only. The agent executes `block_wan`, `quarantine`, `restore`
and `restore_all`; `power_cycle` is rejected. A high displayed/Gemini-adjusted
risk score alone does not authorize restriction. Restore permits reconnection
and does not repair a device. Learning mode does not release existing restrictions.

The runtime serializes capture processing, policy, command execution and uploads.
A bounded capture queue can drop traffic under overload; such loss limits detection.
Regular successful cloud cycles are scheduled at 0.5 seconds, with error backoff
up to 30 seconds. The direct-loopback listener class is not currently wired into
this runner; see [Pi control status](../docs/PI_DIRECT_CONTROL.md).

State directory records include `state.json`, `enforcement.json`, `cloud.json`,
`outbox.jsonl`, `routine.json`, `discovered-devices.json`, and `presence.json`.
Use one process per directory and separate replay/Linux state. Journals retain
uncertain intent and exact upload/ack payloads; they do not establish exactly-once
physical execution. Stop the agent before local panic. Do not delete its journals
as an ordinary way to unquarantine a device.

## Tests and guides

```bash
agent/.venv/bin/python -m pip install -r agent/requirements-test.txt
agent/.venv/bin/python -m pytest agent/tests ml/tests tests -q
```

Current counts/failures are in [the review](../docs/RECENT_CHANGES.md#verification-and-known-gaps),
not a blanket claim that all tests pass. The isolated decoy/firewall Docker labs
exercise actual packets, with hostapd stubbed in the firewall lab. Public `--live`
CLI requirements differ from the lab helpers' injected mock/test configuration.

- [Integration](INTEGRATION.md): worker boundaries and telemetry contract.
- [Cloud runner](CLOUD_RUNNER.md): queue, retries, live-only server behavior.
- [Decoys](LIVE_DECOYS.md): real TCP listeners and packet attribution.
- [Linux enforcement](LINUX_ENFORCEMENT.md): AP controls, panic and hardware checks.
- [Startup snapshot discovery](../scripts/STEP2_DISCOVERY.md): separate review tool.
