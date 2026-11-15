# Trained model integration

Reviewed at `332f573` on November 15, 2026. The scan artifact/feature adapter did
not change in the post-9 p.m. review; live discovery, presence, server mode and
UI did. See [recent changes](../docs/RECENT_CHANGES.md).

The agent now uses `ml/data/scan_model.joblib` in the default replay CLI path.
The trusted repository bundle contains a calibrated classifier, the feature list,
and threshold 0.95 (latest re-trained bundle). `ml/requirements-model.txt` supplies C's pinned dependencies.
No retraining was performed in this integration.

## Run

From the repository root:

```bash
agent/.venv/bin/python -m pip install -r agent/requirements-test.txt
agent/.venv/bin/python agent/agent.py --replay agent/fixtures/arp_scan.pcap --arm
agent/.venv/bin/python -m pytest agent/tests ml/tests -q
```

The printed Model status includes `active`, the artifact SHA-256, feature order,
threshold, and number of predictions. `--model-mode required` is the default and
fails if the bundle/dependencies cannot load. `--model-mode auto` explicitly
reports fallback. `--model-mode rules` explicitly disables trained predictions.
The separate `--simulate` walkthrough remains a scripted rule demo.

For Docker-hosted API/dashboard, run the platform's Compose instructions on a
machine with Docker available. Run the agent on the host with
`SECURIOT_API_URL=http://localhost/api` (or the configured loopback port/prefix)
and the API's AGENT_API_KEY for live operation. The normal API now rejects
simulated replay ingest with 409, including in memory mode. Replay HTTP tests
use isolated non-live Settings; do not upload fixtures to the normal server.
HTTPS is required for non-loopback endpoints. Compose currently hosts the API and Caddy/React;
it does not create a Linux router or live-capture agent service.

## Training/inference compatibility

C's shared `Window` extracts these features in saved order:

`arp, targets, ips, ports, bytes, arp_rate_1s`

The shared Window also calculates `new_ratio`; C's newest training commit drops
that feature. The adapter extracts the shared vector and selects the saved subset
in its exact saved order, validating estimator feature metadata.

Training counts frames whose source MAC is the device and records the feature
vector at the first outgoing packet of each observed second. The adapter now:

- feeds all outgoing frames into that same Window, including warmup history;
- excludes incoming replies from trained-model features while retaining inventory
  byte accounting in both directions;
- predicts once per observed second, not once per packet;
- requires two over-threshold adjacent observed seconds, resetting on gaps,
  at least 8 ARP requests or distinct SYN targets, and 10 seconds between model alerts;
- validates class labels, feature order, finite scores, and threshold range;
- applies a local threshold floor of 0.9 without lowering the saved 0.95 threshold;
- bypasses C's current per-packet model path so it cannot double-predict/count packets
  as consecutive windows.

Model evidence is a binary `scan_like` warning. For the existing cloud contract it
is exported as `scan_targets` with explicit model basis/classification evidence;
it does not claim a malware family or exact attack subtype. These model-only
warnings remain advisory during transfer testing. Strong decoy/ARP rules can
still request containment on the selected backend through automatic safety
checks. Manual commands have separate override semantics; see LINUX_ENFORCEMENT.md.

The adjacent-second requirement is stricter than C's evaluation script, which
shifts consecutive observed rows without requiring adjacent wall-clock seconds.
The script's metrics below therefore are not measurements of this agent's full
policy or hardware response.

## Evaluation observed during integration

The earlier November 14 integration recorded these results from
`ml/tools/evaluate.py --test-only`; this documentation review did not retrain or
rerun the dataset evaluation:

| Evaluator | Held-out episodes found | Episode recall | False alerts/device-hour | Median detection time |
| --- | --- | --- | --- | --- |
| Trained model (latest bundle) | 1218 / 1525 | 0.80 | 0.01 | 5 s |
| Threshold baseline | 537 / 1525 | 0.35 | 0.00 (rounded) | 14 s |

The test split contains Amazon Echo and Samsung Camera traces; the script reports
2746.84 normal device-hours. The checked-in training pipeline builds scan labels
by injecting synthetic sweeps into UNSW traces. The visible files do not establish
training on CICIoT attacks, a Pi holdout, or detection of arbitrary real attacks.
The threshold baseline here also differs from the agent's ARP distinct-target and
containment safeguards. Treat these figures as C's dataset evaluation, not demo
accuracy or a containment SLA.

## Verification and live operation

Current tests exercise artifact loading/predictions, saved feature order and
cadence, incoming exclusion, model-only advisory behavior and isolated API/SQLite
round trips. The broader suite has unrelated integration failures documented in
[the current review](../docs/RECENT_CHANGES.md#verification-and-known-gaps); do not
reuse an old all-green count as today's validation.

The historical `tools/smoke_stack.py` combines replay telemetry with a normal
API process. Its earlier passing results predate live-only ingest and must not
be presented as a fresh pass without adjusting/revalidating that isolated harness.
The normal production/development API rejects simulated source data.

The real live CLI requires Linux enforcement/discovery and starts without
`--devices`; use [LINUX_ENFORCEMENT.md](LINUX_ENFORCEMENT.md). It honors the same
required/auto/rules model modes. Device identity and presence do not alter trained
feature units or prove transfer accuracy. PR #18's reported live presence/ingest
checks are separate from independently labeled Pi attack/normal evaluation.

Physical AP visibility, Wi-Fi isolation/rejoin, capture overload, installed model
versions, persistent deployment and real attack accuracy need their own recorded
acceptance. Model availability does not imply coverage of every threat family.
