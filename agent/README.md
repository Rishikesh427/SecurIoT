# SecurIoT agent: packet replay, cloud loop, and evidence checks

This is Worker A's offline development slice from the [V3 build plan](https://docs.google.com/document/d/1VMV0LMaaC6DO5OXcdFnvUauciE278WBpgJ2sXGo0xIM/edit?tab=t.n4h3all1s3x3):

**Packets → local detector/scorer → safety decision → mock action → durable event → optional cloud delivery.**

It runs with Python 3.11+. The original summary walkthrough uses only the standard library; packet-file replay uses optional Scapy. The optional connected runner uploads to the cloud. Live capture and real firewall changes remain future work.

**Current stage: standalone offline agent.** It reads packets from files, calculates traffic features, evaluates preview scan rules, applies safety checks, performs mock actions, and saves events. Worker C's detection/scoring is connected for offline replay; Worker B's ingest/sync/ack routes are connected through the optional runner; Linux network controls remain pending. See [how the tracks fit together](INTEGRATION.md).

## Cloud runner and expanded threat tests

See [CLOUD_RUNNER.md](CLOUD_RUNNER.md) for connected replay, environment setup,
reconnect behavior, and the trained-model adapter handoff. See
[THREAT_COVERAGE.md](THREAT_COVERAGE.md) for tested signals, vulnerability evidence,
and explicit detection gaps.

```bash
agent/.venv/bin/python -m pip install -r agent/requirements-test.txt
agent/.venv/bin/python -m pytest agent/tests ml/tests -q
```

## Combined agent + Worker C testing

Worker C's actual detector/scorer is now the default for the replay CLI. From the repository root:

```bash
agent/.venv/bin/python -m pip install -e 'agent[replay]' -e ./ml pytest
agent/.venv/bin/python -m pytest agent/tests ml/tests -q
```

This runs both tracks' unit tests and the combined packet → C detector/scorer → local safety → mock action tests. The ML package must be installed editable because its reference JSON data currently lives alongside its source directory.

Compare a supporting warning with an actionable scan:

```bash
agent/.venv/bin/python agent/agent.py --replay agent/fixtures/scan.pcap --arm
agent/.venv/bin/python agent/agent.py --replay agent/fixtures/arp_scan.pcap --arm
```

With fresh state, the first reports `supporting_evidence_only` and keeps the device normal; the second applies mock quarantine. Omit `--arm` for learning mode. Pass a fresh `--state-dir` to isolate repeated experiments from saved mock restrictions. Use `--detector preview` to explicitly select the earlier preview behavior; the original `--simulate` walkthrough still uses its demo detector.

C receives per-packet ARP/SYN deltas and owns its own 10-second window. C's `scan_arp`/`decoy_touch` findings with anomaly ≥0.5 are eligible for containment, with at least eight distinct ARP targets additionally required for ARP-only containment; target scans and volume findings remain advisory. Packet replay supplies ARP/SYN activity and explicitly configured TCP decoy hits (`--decoy-ip`). Risk uses C's `assess()` and its native 0–1 anomaly scale. The strongest observed anomaly is retained for this replay session; decay and persistence of that score are future work. Baseline files are not automatically enabled because their traffic interval must be agreed before connecting volume measurements.

Device JSON can optionally supply reported `ports`, `vendor`, `model`, `eol`, `default_creds`, and `cloud_only` facts for assessment. A bounded `persona` is allowed only when the input explicitly says `simulated: true`. Scanned destination ports aren't evidence that a service is open on the source device. The CLI shows C's native confidence labels; mapping them into the cloud contract remains a cloud-adapter task.

## Replay packet files

The replay environment has been created locally at `agent/.venv`. To set it up on another machine, run from the repository root:

```bash
python3 -m venv agent/.venv
agent/.venv/bin/python -m pip install -e 'agent[replay]' -e ./ml
```

On Windows PowerShell, use `py -m venv agent/.venv` and `agent\.venv\Scripts\python.exe` in place of the Unix environment path below.

Start with a generated scan capture in learning mode:

```bash
agent/.venv/bin/python agent/agent.py --replay agent/fixtures/scan.pcap
```

You should see one supporting scan finding and no restriction. To exercise actionable ARP detection with mock quarantine:

```bash
agent/.venv/bin/python agent/agent.py --replay agent/fixtures/arp_scan.pcap --arm
```

Try `normal.pcap`, `slow_targets.pcap`, and `protected_arp.pcap` in the same folder. The [fixture guide](fixtures/README.md) explains each expected outcome. The captures are **generated test data**, not recordings from real devices. The parser really reads their encoded headers and timestamps; there is no filename-to-outcome shortcut.

For your own Ethernet capture, configure its known devices:

```bash
agent/.venv/bin/python agent/agent.py --replay /path/to/capture.pcap --devices /path/to/devices.json
```

`devices.json` is an object with a `devices` array; each entry has `mac`, `ip`, `name`, and an optional boolean `protected`. See `agent/fixtures/devices.json`. All replay enforcement is marked simulated, including when replaying a real recording. Unconfigured devices are counted as unmatched, not made eligible for actions automatically. Packet collection is not full DHCP discovery yet.

The collector maintains a sliding 10-second window per known MAC. It counts ARP requests, **distinct** destination IP/port pairs from SYN-without-ACK packets, captured frame bytes in each direction, destinations, and DNS query names. Incoming replies don't become outgoing scan attempts, and rolling window totals don't get added repeatedly to lifetime counters. A threshold preview reports crossings and periodically rechecks continuing scans so startup warmup doesn't hide an ongoing scan.

Replay streams Ethernet PCAP/PCAPNG, including VLAN-tagged frames and basic IPv4/IPv6 traffic. DNS extraction currently covers UDP queries to port 53; encrypted DNS, TCP DNS reassembly, and raw Wi-Fi/Linux cooked link layers are outside this slice. Unsupported link-layer frames are counted; an entirely unsupported capture is rejected. Malformed file headers and decreasing timestamps stop replay with an error. Packet processing is single-threaded; a per-device window cap stops oversized windows instead of silently undercounting. This is an offline correctness harness, not a real-time throughput claim.

Packet-file decoding uses [Scapy's capture readers](https://scapy.readthedocs.io/en/stable/api/scapy.utils.html).

Capture spacing is preserved without sleeping. Original capture timestamps are recorded in detection evidence and mapped onto the replay session clock for safety timers; event timestamps are replay-session times. The 30-second warmup is **enforced**, so a short capture can produce a finding with action suppressed by warmup. Generated fixtures include activity past that boundary.

Replay state uses `agent/runtime/replay/`, separate from the original walkthrough. It preserves mock restrictions across runs. Use `--state-dir` with a fresh directory for independent experiments; interrupted/corrupt replays may already have appended earlier events, which stay local. Cloud upload is opt-in using `--connect`; enforcement stays mocked.

## Run from the repository root

Start in learning mode:

```bash
python3 agent/agent.py --simulate
```

Walk through mock quarantine, Restore, restore grace, protected devices, and Restore all:

```bash
python3 agent/agent.py --simulate --arm
```

On Windows, use `py` in place of `python3` if needed. The `--arm` flag only enables the **mock** enforcer. Each agent startup defaults to learning mode, including after a restart. The walkthrough advances a simulated clock so you don't wait through warmup or grace periods; its timestamps can be ahead of wall-clock time.

You can also run `python3 -m securiot_agent --simulate --arm` from inside `agent/`. An optional editable install, `python3 -m pip install -e agent`, provides the `securiot-agent` command.

## What you should see

1. Normal camera traffic produces no finding.
2. A synthetic scan produces `would_have: quarantine`; the camera stays normal.
3. With `--arm`, a subsequent scan marks the simulated camera quarantined.
4. Restore returns it to normal and starts a 60-second grace period.
5. A scan during grace is recorded without action.
6. A protected laptop is never automatically restricted.
7. A scan after grace can quarantine the camera again.
8. Restore all clears the remaining mock restrictions.

`quarantine` goes directly to the mock backend in this milestone. The runtime also supports a separate `block_wan` action; a timed, configurable response ladder is future work. Power cycling is explicitly rejected as unavailable.

## Read the code in this order

| File | Responsibility |
| --- | --- |
| `securiot_agent/simulation.py` | The example camera/laptop and the walkthrough you see in Terminal |
| `securiot_agent/models.py` | What a device, observation, finding, and event contain |
| `securiot_agent/inventory.py` | Known devices, traffic counters, and destinations |
| `securiot_agent/detection.py` | The detector interface and clearly labeled demo detector |
| `securiot_agent/policy.py` | Default safety timings and learning mode |
| `securiot_agent/runtime.py` | Connects observations to decisions and actions |
| `securiot_agent/enforcement.py` | Changes mock state; contains no network commands |
| `securiot_agent/storage.py` | Saves restrictions/grace/cooldown and appends audit events |
| `securiot_agent/packets.py` | Reads Ethernet packet headers and capture timestamps from files |
| `securiot_agent/collector.py` | Converts packets into per-device deltas and rolling-window features |
| `securiot_agent/replay.py` | Connects packet files to the same agent and reports results |

The original demo detector checks **already summarized synthetic 10-second windows**, using ≥30 ARP requests or ≥20 distinct IP/port targets. The replay preview uses those thresholds on the collector's actual rolling-window measurements. Neither assigns risk scores or implements Worker C's baselines/assessment package. `Detector.observe()` is a local adapter boundary, not a signature requirement imposed on `securiot_ml`.

## Safety and restart behavior

- Restrictive actions require an explicit Arm, a known MAC, and an unprotected device.
- No new restrictions during the first 30 seconds after startup.
- At most one restrictive action per device per 10 seconds.
- Restore is available immediately, including during warmup, learning mode, and cooldown. It starts a 60-second grace period.
- Restarts return to learning mode but reapply previously saved mock restrictions. Unknown or newly protected devices are skipped when loading saved restrictions.
- Invalid state stops startup with an error rather than silently discarding it.
- All events are marked `simulated: true`, include UUIDs, and are appended to `runtime/outbox.jsonl`. Supported detection records are uploaded only with `--connect`; the full local audit log is retained.
- `runtime/state.json` saves enforcement status and safety timers. Traffic counters are session-local. Runtime files are ignored by Git.
- The walkthrough resets any restrictions from an interrupted earlier walkthrough, with an explicit message, before beginning its example.

Inspect `agent/runtime/outbox.jsonl` after a run. `actions_taken` records mock actions that succeeded; `would_have` records learning-mode proposals. The outbox is the full local audit trail. The cloud adapter exports only supported detection records and preserves the rest locally.

For an isolated run, pass `--state-dir /path/to/scratch-directory`. To reset demo history, use a new directory or remove the simulation runtime files while the agent is stopped.

## Run the tests

From the repository root:

```bash
python3 -m unittest discover -s agent/tests -p test_agent.py -v
```

That command runs only the original standard-library tests. Install `agent/requirements-test.txt` and use pytest to include the packet, cloud, and threat-matrix tests. To run **all** tests, including packet replay:

```bash
agent/.venv/bin/python -m pytest agent/tests ml/tests -q
```

The tests use temporary directories, generated packets, and a controllable clock. They require no Linux privileges or real network traffic. Packet cases cover window expiry, independent MACs, byte accounting, repeated targets, DNS, protected devices, malformed captures, and an ongoing scan spanning startup warmup.

## Later milestones

1. Extend the current C adapter with explicitly configured decoy hits and agreed baseline intervals.
2. Add Scapy packet capture/discovery and decoy listeners on the Linux router.
3. Add nftables enforcement and a local panic command, with rollback tests on Linux.
4. Verify the connected runner against the deployed API/database and integrate dashboard action creation.
5. Add the local API/web bundle, systemd deployment, and optional smart-plug mapping.

The production network and cloud components are intentionally still pending. This directory owns the agent; the other team tracks remain in `api/`, `ml/`, `web/`, `/contract`, and `/sim`.

Current guards: protected devices still raise alerts; only automatic actions are blocked.
ARP quantity needs at least eight distinct targets for containment. Explicit decoy
IPs can be passed repeatedly with `--decoy-ip`. C's current rules remain the default;
the trained artifact is pending. Vulnerability flags distinguish reported/simulated
facts and candidate CVEs, and do not claim a local scan or firmware verification.
