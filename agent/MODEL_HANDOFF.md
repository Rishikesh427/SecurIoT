# Arrived trained model

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
and the API's AGENT_API_KEY. Then add `--connect` to replay. HTTPS is required
for non-loopback endpoints. Compose currently hosts the API and Caddy/React;
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
still request mock containment through the existing safety checks.

The adjacent-second requirement is stricter than C's evaluation script, which
shifts consecutive observed rows without requiring adjacent wall-clock seconds.
The script's metrics below therefore are not measurements of this agent's full
policy or hardware response.

## Evaluation observed during integration

After the teammate's retraining commit, C's `ml/tools/evaluate.py --test-only` produced:

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

## Verified / pending

Verified: actual artifact loading/predictions; exact shared feature vectors;
one-second cadence; no two-packet streak; incoming exclusion; fallback failures;
real-model replay through API login, ingest, real SQLite memory storage, queued
Restore and acknowledgement. Enforcement remains mocked.

Docker was subsequently installed and the isolated Docker smoke test passed:
API and React/Caddy images built; frontend assets were served; API health and
memory-storage mode were verified; the host agent loaded the actual model,
made model predictions, uploaded detection events, and completed authenticated
Restore/acknowledgement through the real command queue. Lost ingest/ack responses
were retried without duplicate events or repeated Restore. The test removed its
own containers/volumes and used no configured external database.

Repeat the isolated test from the repository root:

```bash
agent/.venv/bin/python agent/tools/smoke_stack.py
```

This is an HTTP/API/assets test, not browser interaction QA. Live capture/decoys are also verified in an isolated Docker network (see LIVE_DECOYS.md). Physical Pi capture,
Wi-Fi/firewall behavior, persistent Postgres, public deployment, and independent
Pi attack/normal recordings still need testing.
