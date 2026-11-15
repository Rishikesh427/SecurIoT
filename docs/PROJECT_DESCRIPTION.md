# CasaWarden: Project Description and Technical Reference

Reviewed on November 14, 2026 against repository commit `629a98d`.

**Project name:** CasaWarden was previously called SecurIoT. Existing code and
backend identifiers intentionally retain legacy names such as `securiot_agent`,
`securiot_ml`, `SECURIOT_*`, the `securiot` database schema/Compose project, and
`securiot_guard` firewall tables. Keeping these names preserves imports,
configuration, authentication, persisted state, and enforcement recovery without
an unrelated migration. Existing UI labels, API metadata, and logs may also use
the old name. Commands and paths in this document use their actual implementation
spelling. See the [project naming note](../README.md#project-name-and-compatibility).

This document consolidates all 13 Markdown documents in the repository and checks their claims against the current implementation, model artifact, training scripts, API, dashboard, and relevant tests. Where older documentation disagrees with the code, this document describes the implemented path and identifies the difference. It is a source document for the demo presentation, rather than a claim that every deployment or hardware test has been completed.

## 1. What CasaWarden does

CasaWarden is a network security prototype for smart devices such as cameras, speakers, plugs, printers, and projectors. It combines device inventory, traffic analysis, a trained scan classifier, vulnerability risk assessment, a dashboard, and optional network containment.

Its central idea is to protect devices at the network boundary when their firmware is difficult to update or their owners cannot easily assess their security. A local agent observes traffic, detects selected suspicious behaviors, checks safety policy, and can restrict an eligible device. The dashboard explains the findings and lets the user review risk, request quarantine, restore access, and inspect the action history.

Gemini provides plain-language explanations and device-specific suggestions. Detection and enforcement run locally and do not require Gemini to make a decision.

The current implementation provides three distinct types of evidence:

| Evidence | What it means | How CasaWarden uses it |
| --- | --- | --- |
| Configured device facts | Reported ports, vendor/model, support status, credentials, and cloud dependency | Static risk scoring and hardening advice |
| Observed behavior | Packet-derived scans, decoy contacts, traffic volume, and device appearance | Events, behavioral risk, and containment eligibility for selected strong signals |
| AI interpretation | Gemini's assessment, explanations, suggestions, and fix ordering | Dashboard assistance, with a bounded display-score adjustment |

A high risk score is a reason to review a device. It is not, by itself, an automatic quarantine trigger or proof of infection.

## 2. Architecture and data flow

The repository is organized around four main components and a shared contract.

| Component | Location | Responsibility |
| --- | --- | --- |
| Local agent | `agent/` | Packet capture/replay, inventory, detection, risk assessment, safety checks, local state, and enforcement |
| ML and advice package | `ml/` | Shared traffic features, trained classifier, rules, score weights, catalog data, Gemini helpers, and audit digest |
| Backend API | `api/` | Authentication, telemetry ingestion, device/event reads, policy, command queue, explanations, advice, and audit |
| Web dashboard | `web/` | Overview, device list/map, risk explanations, manual controls, advisor, activity, and settings |
| Shared contract | `contract/` | JSON schemas, sample telemetry, action/policy definitions, and example hardware inventory |
| Deployment | `deploy/`, `compose.yaml` | Caddy, API/frontend containers, storage guidance, and optional public HTTPS tunnel |

The primary processing path is:

```text
Live interface or saved packet capture
    -> Packet parser and per-device collector
    -> Rules + trained scan model + optional calibrated volume baseline
    -> Finding and local risk assessment
    -> Safety policy and response selection
    -> Mock enforcement or explicitly enabled Linux enforcement
    -> Durable local event/outbox
    -> Authenticated API ingestion
    -> Database, dashboard, audit, and optional Gemini explanations
```

User actions follow a separate round trip:

```text
Dashboard Quarantine / Restore
    -> Authenticated API command queue
    -> Agent policy/command polling
    -> Local validation and enforcement
    -> Agent acknowledgement and telemetry
    -> Updated audit outcome and device status in dashboard
```

The agent polls the connected API approximately every two seconds. The dashboard also refreshes devices, events, and related state approximately every two seconds. A queued command is displayed as pending until the agent reports its outcome; clicking a control does not directly change device status.

Sources: [integration](../agent/INTEGRATION.md), [live runner](../agent/securiot_agent/live.py), [cloud loop](../agent/securiot_agent/cloud_loop.py), [API routes](../api/main.py), [dashboard](../web/src/App.tsx).

## 3. Device discovery, inventory, and traffic visibility

### 3.1 Reviewed inventory discovery

`scripts/discover_devices.py` builds an inventory from Linux IPv4 neighbor-cache records and optional dnsmasq DHCP leases. It produces an agent-compatible device file plus discovery provenance.

New entries default to protected. The operator reviews the inventory before loading it into the agent. The script can merge a previous reviewed inventory while preserving configured names, protection, and risk facts. Conflicting IP assignments stop generation.

This path sends no active network probes. A lease or cache entry identifies a candidate device; it does not verify the device's identity, exact product, firmware, or current presence. The standalone script loads changes on restart.

### 3.2 Optional discovery while live capture is running

Newer code also implements an opt-in guest-discovery path through `SECURIOT_DISCOVERY_CONFIG` and `agent/securiot_agent/demo_discovery.py`.

It can register IPv4 LAN sources observed in captured packets and poll neighbor-cache/DHCP information in the background. It adds the device to inventory and collection, emits a `new_device` event, and persists discovery metadata. Defaults protect newly discovered guests. The example configuration limits the inventory to 128 devices; the implementation permits a configured maximum up to 1,000.

It rejects invalid/multicast identities, excluded MACs, subnet/broadcast addresses, and conflicting IP claims. Names inferred from DHCP remain unverified. Discovery does not establish compromise or infer an authoritative device type.

This is a newer, opt-in demo feature. Older documents that say there is no hot discovery describe the earlier startup-only path.

### 3.3 What the collector measures

The same packet collector feeds replay and live capture. It tracks known devices by MAC and calculates:

- Captured frame bytes received and sent.
- Outgoing ARP request counts and distinct ARP targets.
- Distinct outgoing TCP SYN destination IP/port pairs.
- Destination addresses and supported DNS query names.
- TCP attempts toward explicitly configured decoy IP addresses.
- Rolling ten-second traffic measurements.

Replies and non-SYN TCP packets do not become outgoing scan attempts. Repeated SYNs to the same destination IP/port do not multiply the distinct-target count.

Saved-capture parsing supports Ethernet PCAP/PCAPNG, including VLAN frames and basic IPv4/IPv6 traffic. DNS extraction covers UDP queries to port 53. Encrypted DNS, TCP DNS reassembly, raw Wi-Fi capture formats, and Linux cooked link-layer captures are outside the documented parser coverage.

Live capture uses Scapy on the configured interface. A bounded queue separates capture from processing. Overflow is reported as incomplete detection coverage. The Linux router must actually see the relevant traffic for detection and enforcement to work.

The repository contains a small vendor-prefix lookup with placeholder entries; it is not a comprehensive product fingerprinting database. The integrated vulnerability assessor primarily uses explicit device facts. Gemini may suggest an unknown device's likely type, but that remains a labeled hypothesis.

Sources: [discovery guide](../scripts/STEP2_DISCOVERY.md), [startup discovery](../scripts/discover_devices.py), [live discovery](../agent/securiot_agent/demo_discovery.py), [collector](../agent/securiot_agent/collector.py), [vendor hints](../ml/data/vendors.json).

## 4. The machine-learning model

### 4.1 Actual model in the repository

The checked-in artifact is `ml/data/scan_model.joblib`. It contains a binary classifier that distinguishes benign-looking traffic from scan-like activity.

| Property | Implementation |
| --- | --- |
| Base estimator | scikit-learn `HistGradientBoostingClassifier` |
| Tree depth | `max_depth=4` |
| Class weighting | `class_weight="balanced"` |
| Calibration | `CalibratedClassifierCV`, isotonic method, three-fold calibration |
| Output | Score for class `1`, representing scan-like activity |
| Saved alert threshold | `0.95` |
| Saved features | Six features in a fixed, validated order |
| Agent model modes | `required`, `auto`, or `rules` |

The README mentions Isolation Forest. The current training script and inspected artifact instead use calibrated histogram gradient boosting. The model is a scan classifier, rather than a malware-family classifier or a general exploit detector.

### 4.2 Model inputs

The shared `Window` calculates features over a rolling ten-second window. The trained model uses these six, in this order:

| Feature | Meaning |
| --- | --- |
| `arp` | Outgoing ARP request count in the window |
| `targets` | Distinct outgoing TCP SYN destination IP/port pairs |
| `ips` | Distinct destination IPs represented in those SYN pairs |
| `ports` | Distinct destination ports represented in those SYN pairs |
| `bytes` | Captured bytes in outgoing frames included in the window |
| `arp_rate_1s` | ARP requests within the most recent one-second interval |

The extractor also calculates `new_ratio`, but training deliberately excludes it because it is sensitive to restarts and synthetic-injection artifacts.

Incoming replies remain part of inventory byte accounting but are excluded from the trained model's outgoing-traffic features.

### 4.3 Training data and labeling

The checked-in pipeline uses UNSW device traces and injects synthetic sweep episodes into the feature-extraction stream. It also includes benign burst examples. The ingestion code supports separately supplied live interval labels, but the saved split lists seven UNSW traces.

| Split | Device traces |
| --- | --- |
| Training | HP Printer, Nest DropCam, TP-Link Camera |
| Validation | Belkin Wemo Motion Sensor, Samsung SmartThings |
| Held-out test | Amazon Echo, Samsung Camera |

The training script drops positive rows with fewer than eight ARP requests and fewer than eight SYN targets, treating these weak early-sweep rows as ambiguous. It splits by capture file rather than randomly mixing rows from each capture across the train/test split.

These files support a claim of training on normal device traces with synthetic scan injections. They do not establish training on the full CICIoT attack dataset, arbitrary real malware, or independently captured Pi attack traffic.

### 4.4 Agent inference and alert gates

The integrated agent aligns inference with training:

1. Feed outgoing frames into the shared ten-second feature window, including warmup history.
2. Predict on the first outgoing packet in each observed second.
3. Require a score at or above the effective threshold and at least eight ARP requests or distinct SYN targets.
4. Require two qualifying adjacent observed seconds; a gap resets the streak.
5. Limit repeated model alerts for one device to once per ten seconds.

The local threshold floor is `0.9`; the saved threshold of `0.95` remains in effect for the current artifact. Model loading validates feature order, feature count, class labels, threshold range, and finite prediction values. Startup reports artifact status, hash, threshold, and prediction count.

The default CLI mode requires the model and fails clearly if it cannot load. `auto` permits an explicitly reported fallback. `rules` disables trained predictions.

Model-only findings are advisory. They are exported as `scan_targets` with explicit `trained_scan_model` / `scan_like` evidence to fit the existing event contract. The adapter sets `containment_allowed=False` for these findings. Strong ARP and decoy rules independently retain their containment eligibility.

### 4.5 Reproduced held-out evaluation

The following command was run during this review:

```bash
agent/.venv/bin/python ml/tools/evaluate.py --test-only
```

| Evaluator | Episodes detected | Episode recall | False alerts per normal device-hour | Median time to detection |
| --- | --- | --- | --- | --- |
| Trained model | 1,218 / 1,525 | 0.80 | 0.01 | 5 seconds |
| Threshold baseline | 537 / 1,525 | 0.35 | 0.00, rounded | 14 seconds |

The script reports 2,746.84 normal device-hours. These are measurements on the checked-in test split and injected scan labels. They are not general classification accuracy, measured physical containment latency, or a guaranteed response time. The evaluation pairs consecutive observed rows; the agent additionally requires adjacent wall-clock seconds, so it is stricter than this evaluator.

Sources: [training](../ml/tools/train.py), [data extraction](../ml/tools/ingest.py), [feature window](../ml/securiot_ml/model.py), [split](../ml/data/split.json), [evaluation](../ml/tools/evaluate.py), [model adapter](../agent/securiot_agent/trained.py), [model handoff](../agent/MODEL_HANDOFF.md).

## 5. Behavioral detection and the corresponding response

The system combines fixed rules, the trained model, decoys, and an optional volume baseline. The following table describes the integrated agent path, not the older preview detector or browser simulator.

| Finding | Detection evidence | Corresponding system response |
| --- | --- | --- |
| Fast multi-host ARP sweep | At least 30 outgoing ARP requests within ten seconds; containment additionally requires at least eight distinct ARP targets | Record `scan_arp`, update behavioral risk, and request quarantine when safety policy permits. If quarantine is disabled but WAN blocking is enabled, fall back to WAN blocking. |
| Repeated ARP resolution toward few hosts | ARP count reaches the threshold but fewer than eight distinct targets are present | Record supporting evidence; do not automatically quarantine on quantity alone. |
| TCP host or port scan | At least 20 distinct outgoing SYN destination IP/port pairs within ten seconds | Record `scan_targets` and add behavioral evidence; no automatic containment from this rule alone. |
| Trained-model scan warning | Two adjacent qualifying seconds at the model threshold with the minimum signal gate | Record advisory `scan_targets` with explicit model evidence; no automatic containment from the model alone. |
| Decoy contact | An outgoing TCP SYN targets an explicitly configured decoy IP | Record `decoy_touch`; a single hit can request quarantine subject to policy. The rule's anomaly is `1.0` for Telnet ports 23/2323 and `0.9` for other decoy ports. |
| Unusual traffic volume | A complete ten-second byte window exceeds a calibrated device baseline by at least four effective standard deviations | Record advisory `volume`, update temporary behavioral risk, and recommend review; no automatic containment. |
| Newly discovered device | The optional live discovery path registers a new LAN MAC/IP | Record `new_device`, add inventory, and apply configured guest protection defaults; discovery itself does not request containment. |
| New-domain event | Supported by the event contract and explanations | The current integrated detector does not implement a domain novelty/beacon classifier. Collecting DNS queries does not establish that detection. |

### 5.1 Decoy services

`agent/tools/decoy.py` creates real accept-and-close TCP listeners. The documented example ports are `23`, `2323`, `80`, `445`, `554`, and `8080`.

These listeners provide destinations whose unexpected use can be investigated. They do not read credentials, execute commands, or expose an intentionally exploitable Telnet/SMB implementation. Decoy IP aliases must be configured separately. The sniffer attributes traffic using observed Ethernet source MACs; the service's optional configured IP-to-MAC mapping is labeled as configuration-derived.

A legitimate scanner can contact a decoy. The finding is suspicious activity, not proof of malicious intent.

### 5.2 Calibrated volume baselines

The newer `Routine` implementation supports a separate per-device volume baseline:

- Calibration is explicitly requested on the agent host; it does not start automatically.
- It collects 30 complete, clean ten-second windows, approximately five minutes of eligible observation after startup/partial-window exclusions.
- Learning mode is required for calibration. Restricted devices, recent signals, decoy contacts, scan activity, and tainted windows are excluded.
- The resulting mean and sample standard deviation are frozen and persisted until recalibration.
- Detection uses `max(baseline_std, 1024 bytes)` as the effective standard deviation and reports when `z >= 4`.
- Volume anomaly strength is capped at `1.0`, calculated as `min(1, z / 8)`.
- Incomplete windows are discarded after restart; long scheduling/capture gaps are not treated as reliable idle traffic.

This baseline uses inbound plus outbound captured bytes per fixed interval. It is separate from the trained classifier's outgoing-frame byte feature. It does not yet learn a full destination schedule or time-of-day behavior profile.

### 5.3 Behavioral risk expiration

Active behavioral signals are persisted and expire 300 seconds after the latest detection. A new detection renews the expiry while retaining the strongest still-active signal. The runtime can update risk even when no new packet arrives, using `snapshot_at` separately from the last observed packet time.

Expiration lowers the behavioral risk contribution. It does not automatically release a restriction or certify the device as safe.

Sources: [rule detector](../ml/securiot_ml/detect.py), [adapter](../agent/securiot_agent/ml_adapter.py), [runtime](../agent/securiot_agent/runtime.py), [routine](../agent/securiot_agent/routine.py), [decoy documentation](../agent/LIVE_DECOYS.md), [threat coverage](../agent/THREAT_COVERAGE.md).

## 6. Vulnerability assessment and remediation

### 6.1 What “scanning for vulnerabilities” means in this build

The implemented vulnerability path assesses reported device facts against scoring rules and a cached known-exploited-vulnerability catalog. It does not actively port-scan the device, attempt passwords, verify its firmware, or run exploit probes.

The distinction matters for the demo: the agent observes network behavior, while static weaknesses such as default credentials or end-of-life status must be supplied as reviewed facts or explicitly labeled simulation data.

### 6.2 Vulnerabilities and configuration risks

| Weakness / risk factor | Evidence used | Risk contribution | What CasaWarden does | Corresponding operator action |
| --- | --- | --- | --- | --- |
| Candidate known-exploited vulnerability | Normalized exact vendor AND product match against cached KEV entries | +15 total for a possible match | Produce candidate CVE flags, provenance, and applicability caveat; include in risk/advice | Verify exact firmware/configuration against the advisory, update if supported, or restrict/replace the device as appropriate |
| Confirmed KEV applicability | Supported by the lower-level scorer, but not established by the integrated assessor | +30 exists in the score weights, but is not awarded as confirmed by this path | Retain conservative candidate status because a firmware applicability evaluator is absent | Verify applicability outside this implementation before describing a CVE as confirmed |
| Default or weak credentials | Explicit `default_creds=true` fact | +25 | Raise risk; show a dedicated dashboard issue and password-change advice | Change credentials in the device's own settings and verify the change |
| End-of-life / unsupported product | Explicit `eol=true` fact | +20 | Raise risk; show support-status issue and replacement/isolation guidance | Verify support policy, limit exposure, or replace the device |
| Risky management/service ports | Reported service ports from the table below | +15 once for the port factor | Create service-review flags and raise risk | Review which services are needed; disable or restrict unused services in the device/network configuration |
| Reported HTTP admin interface | Port 80/8080 AND explicit membership in `admin_ports` | +15 as the same port factor | Add admin-port risk only when explicitly reported | Use a secure management option where available and restrict administrative access |
| Cloud-only dependency | Explicit `cloud_only=true` fact | +5 | Raise risk and offer dependency/egress review advice | Review cloud dependency and restrict access only if the device's required functions permit it |
| Recent anomalous behavior | Active detector signal on the local 0–1 scale | Up to +40 before the total score cap | Raise temporary risk; selected strong signals may separately request containment | Review evidence and use quarantine/restore controls when appropriate |

Static risk factors alone do not automatically quarantine devices. Manual containment remains available when local/cloud policy permits it. Password changes, firmware updates, service configuration, replacement, and CVE applicability review are operator tasks; CasaWarden does not perform those repairs.

### 6.3 Ports covered by the integrated assessor

| Port | Service / review category | Exact treatment |
| --- | --- | --- |
| 21 | FTP | Service-review flag and port-factor eligibility |
| 23, 2323 | Telnet | Service-review flag, port-factor eligibility, and dedicated dashboard hardening guidance |
| 445 | SMB | Service-review flag and port-factor eligibility |
| 1900 | UPnP / SSDP | Service-review flag and port-factor eligibility |
| 5000 | UPnP candidate | Candidate service review and port-factor eligibility; the port does not prove protocol identity |
| 5555 | ADB candidate | Candidate service review and port-factor eligibility |
| 7547 | TR-069 candidate | Candidate service review and port-factor eligibility |
| 80, 8080 | HTTP | Review flag; admin-port risk requires explicit `admin_ports` evidence |

Multiple listed ports do not each add 15 points; the port factor contributes 15 points once. A device probing a destination port is not evidence that this service is open on the probing device.

### 6.4 CVE catalog coverage and confidence

The checked-in `ml/data/kev.json` contains 1,781 entries, catalog version `2026.11.13`, released `2026-11-13T20:24:18.3008Z`. These describe the repository's stored snapshot, rather than a live catalog check.

The integrated assessor normalizes case/punctuation and requires exact vendor/product identity. It rejects malformed CVE IDs and reports catalog age/version, missing facts, and the number of matching entries. Individual candidate flags are bounded to ten per assessment.

No match means that this matching process found no candidate in the cached catalog. It does not establish that the product has no vulnerabilities. Product aliases, model families, firmware versions, and configuration applicability are not comprehensively evaluated. The legacy `ml/securiot_ml/kev.py` helper uses looser matching, but the integrated agent uses the more conservative `VulnerabilityAssessor`.

### 6.5 Risk formula and example

The implemented weights are:

```text
Rules risk = min(100,
    KEV points
    + default-credential points
    + end-of-life points
    + port-factor points
    + cloud-only points
    + round(40 * active behavioral signal))
```

Risk bands are low `0–29`, medium `30–59`, and high `60–100`. The code uses +5 for cloud-only operation, although the root README says +10.

The simulated camera example scores 75:

```text
Possible KEV factor     15
End-of-life             20
Telnet/service ports    15
Default credentials     25
Total                   75 / 100
```

Its persona and factor values are simulation data. They are not evidence that a real demo camera has those weaknesses. The score is capped at 100, so the visible increase from behavior can be smaller than its uncapped contribution.

Sources: [integrated assessor](../agent/securiot_agent/vulnerabilities.py), [score weights](../ml/securiot_ml/rules.py), [scorer](../ml/securiot_ml/score.py), [inventory assessment command](../scripts/assess_inventory.py), [fixtures](../contract/fixtures.json), [catalog snapshot](../ml/data/kev.json).

## 7. Containment, recovery, and safeguards

### 7.1 Available actions

| Action | Linux enforcement behavior | Recovery / limitation |
| --- | --- | --- |
| `block_wan` | MAC-based nftables filtering blocks outbound forwarding and return traffic for IPv4/IPv6 | Local/router access remains available; routed traffic must traverse the enforcement host |
| `quarantine` | Filters Ethernet ingress/egress, including ARP/IPv6; adds a hostapd deny entry; disconnects the station and checks denial/association state | Requires the configured Linux AP and supported nftables/hostapd environment |
| `restore` | Removes CasaWarden-owned firewall and Wi-Fi denial for the device | Permits reconnection; does not force the client to reconnect or repair its firmware/software |
| `restore_all` | Attempts recovery for all known restricted devices, including known pending partial restrictions | Reports partial failures rather than claiming complete recovery |

Replay and the original simulation use a mock backend. Live capture also defaults to mock enforcement. Real actions require Linux, root privileges, explicit enforcement configuration, `SECURIOT_REAL_ENFORCEMENT=yes`, real-device records, and the Linux backend selection.

The required topology is a routed, unbridged access point with a separate uplink. The backend does not provision Wi-Fi, DHCP, NAT, routing, or internet sharing. The documented backend requires Linux 5.16+ with suitable nftables netdev egress support. Flowtable acceleration and bridged interfaces are rejected by preflight.

### 7.2 Response selection

The runtime contains score-based response selection with notification, WAN block, and quarantine tiers. Generic eligible findings use thresholds around `0.95`, `0.97`, and `0.99`; continuing eligible activity after a WAN block can escalate to quarantine.

For the integrated rules, eligible strong ARP sweeps and decoy touches directly request quarantine. They do not have to move through a timed notification/block/quarantine sequence. If quarantine is disabled, the runtime can fall back to WAN blocking. If both restrictions are disabled, no restrictive action is chosen.

These thresholds use detector evidence, not the dashboard's 0–100 risk or Gemini-adjusted display score. Model-only and volume findings remain advisory regardless of how high the displayed risk becomes.

### 7.3 Safeguards

- Every agent startup begins in learning mode; local arming must be explicitly granted.
- Connected automatic enforcement also respects cloud learning mode and enabled policy steps.
- Protected devices remain observable, but restrictive actions are rejected. Controller/router MACs receive additional protection in the Linux backend.
- Automatic restrictions have at least 30 seconds of startup warmup.
- Automatic restrictions have at least ten seconds of per-device cooldown.
- Restore starts at least 60 seconds of grace against automatic containment.
- Manual quarantine bypasses automatic warmup, cooldown, and restore grace, but still respects arming, learning mode, protection, and enabled steps.
- Restore remains available while unarmed or in learning mode.
- Switching to learning mode does not automatically clear saved restrictions.
- Durable journals distinguish intended, confirmed, failed, and uncertain actions across restarts.
- A local panic command can remove CasaWarden-owned restrictions after stopping the running agent.

The Linux backend operates on its own named tables and owned Wi-Fi deny entries; it preserves unrelated firewall tables and external bans. A partial failure can leave some restrictions applied and is reported as a failure requiring recovery.

The repository rejects `power_cycle` as unavailable. It does not implement the Bluetooth shutdown or smart-plug power-cycle behavior suggested by some early project language. MAC-based containment also does not provide permanent authentication against a client changing its MAC.

Sources: [Linux enforcement guide](../agent/LINUX_ENFORCEMENT.md), [enforcement backend](../agent/securiot_agent/linux_enforcement.py), [runtime](../agent/securiot_agent/runtime.py), [safety timings](../agent/securiot_agent/policy.py), [cloud command handling](../agent/securiot_agent/cloud_loop.py).

## 8. Gemini-powered suggestions and explanations

Gemini is an optional server-side advisory service configured through `GEMINI_API_KEY` and `GEMINI_MODEL`. The project does not hard-code one Gemini model name. Credentials stay out of the browser bundle.

### 8.1 Event explanations

For supported events, the API immediately returns a deterministic template and can schedule a Gemini explanation in the background. Later polls receive validated generated text when available.

The explanation contains a short observation and recommended next step. The server adds the recorded action outcome separately, distinguishing proposed containment, reported WAN blocking, reported quarantine, restore, and simulation. Generated wording is checked for unsupported claims of completed actions or definite infection/repair.

Volume findings deliberately retain deterministic advisory explanations without requesting Gemini generation.

The explanation pool has two workers, a maximum of four running/queued jobs, an eight-second service deadline, and a provider timeout up to six seconds. Its cache holds up to 512 entries; successful results last one hour, and failures retry after 60 seconds. Ordinary event reads do not wait for generation.

### 8.2 Per-device assessment and hardening suggestions

The device advisor returns:

| Field | Purpose |
| --- | --- |
| Assessment | Plain-language interpretation of the supplied facts |
| Likely type | Labeled guess for unknown/generic devices; authoritative device type is unchanged |
| Expected behavior | Explicit hypothesis about normal use, rather than measured behavior |
| Top risk | Main concern based on recorded factors |
| Next step | One concrete hardening/review suggestion |
| Confidence | Low, medium, or high confidence in the advisory assessment |
| Display adjustment | Integer adjustment capped at ±10, with a reason for nonzero changes |

Examples of rule-based fallback suggestions include changing a default password, replacing or isolating an unsupported device, disabling Telnet, and reviewing updates/unused services.

The displayed score is `clamp(rules_risk + delta, 0, 100)`. Low-confidence advice forces the adjustment to zero. The rules score and its color band remain authoritative. These AI fields do not enter agent synchronization or enforcement.

### 8.3 Device-specific chat

Users can ask questions such as “What should I do first?”, “Is it safe to keep this device?”, and “How do I harden it?”. The API supplies facts about the selected device, a bounded question, and up to six recent conversation turns. Answers are limited to 120 words.

Chat has no tools. It cannot run scans, change settings, modify scores, issue commands, quarantine, or restore a device. It can explain how the user should review the evidence and use existing dashboard/device controls.

### 8.4 Fix prioritization

The **Prioritize devices** feature asks Gemini to order the twelve highest displayed-risk devices by urgency with short reasons. Remaining devices follow in score order. The server requires each supplied opaque device ID to appear exactly once; invalid/incomplete output falls back to the full rules-based order.

### 8.5 Data sent and failure behavior

Event explanations receive allowlisted counts, ports, flags, and bounded device factors. They exclude raw packets, arbitrary evidence dictionaries, addresses, device names, DNS names, and banners.

The advisor receives a somewhat broader allowlist: device name/vendor/model text, ports, risk factors, status, selected reasons, and recent event kinds. IP/MAC addresses embedded in text or chat are redacted. It excludes raw packet/event evidence and destination lists. Chat questions/history are still sent to the provider after redaction; this is not a claim that arbitrary personal information is removed.

Advisor assessments use a bounded background service with two workers, up to sixteen pending jobs, and a 256-entry cache. Successful assessment/triage results last fifteen minutes; failures retry after 60 seconds. Authenticated chat and triage share a limit of twenty requests per minute per user. Saturation/deadlines can return retryable errors.

Missing credentials, provider errors, or invalid output lead to rules-based advice/templates and zero AI score adjustment. Local detection and enforcement continue without Gemini.

Sources: [advisor helper](../ml/securiot_ml/advisor.py), [advisor API](../api/advisor.py), [event explanation helper](../ml/securiot_ml/explain.py), [explanation service](../api/explanations.py), [advisor interface](../web/src/components/Advisor.tsx).

## 9. Application features

### 9.1 Overview

The React/TypeScript dashboard presents an overall status banner, device count, attention count, restricted-device count, aggregate traffic rate, and a severity-sorted list of issues.

The user can enable automatic protection, open a finding, review its explanation, and follow the available action. New incident events can trigger an alert tone and spoken summary after audio interaction is enabled. Sound can be muted.

Traffic sparklines estimate rates from changes in cumulative agent byte counters, rather than performing an independent browser packet capture.

### 9.2 Device list and network map

The dashboard has list and map views. The Cytoscape map loads on demand and places devices around a router representation. Device rows show risk, status, traffic, simulation/protection labels, and available AI display adjustments. New entries receive an arrival animation.

The map is a visualization of reported inventory, not a separately discovered or verified complete physical network topology.

### 9.3 Device detail

Selecting a device opens a detail panel with:

- Identity and reported vendor/model where available.
- Current reported status, risk band, and simulation/protection labels.
- Manual Quarantine and Restore access controls, with queued state.
- Incident summary and explanation status.
- Gemini assessment, hardening advice, and device chat.
- Rules risk reasons and cleanup instructions.
- Expandable IP/MAC, reported ports, byte totals, destinations, support status, and credential facts.
- Recent events for that device.

The integrated wire adapter currently omits some optional identity fields such as `model` and `kev`, even though the API contract supports them. Local assessment can therefore have more detail than an agent-uploaded dashboard record. Fixtures may include those fields directly.

### 9.4 Fix workflow

The issue list includes learning mode, recent proposed containment, currently restricted devices, and selected standing weaknesses such as reported default credentials, end-of-life status, and Telnet.

Opening **Fix** shows a plain-language explanation, steps, technical details, and an applicable action such as enabling protection, quarantining, or restoring. **I've done this** dismisses the issue in browser-local storage. It does not remotely change a password, re-scan firmware, or verify remediation.

### 9.5 Activity, audit, and digest

The Activity tab includes the event feed, audit log, and **Run audit** digest.

Audit history combines queued-command lifecycle records with detection/action rows derived from stored events. It distinguishes requested, applied, failed, and proposed outcomes. Eligible applied restrictions offer an **Undo** action that queues a Restore command.

The current digest is deterministic and works without Gemini. It summarizes at most the latest 1,000 available audit entries, separates recorded activity from simulator activity and seeded examples, and counts detections, applied actions, pending requests, failures, and proposals. It is not automatically a full-week report.

### 9.6 Settings and operational status

Settings expose automatic protection, response-step toggles, and protected devices. Policy writes use ETags to reject stale updates. The header identifies persistent Tiger Data storage or temporary demo storage. An offline banner reports that the server is unreachable; remote commands remain pending until reconnection.

### 9.7 Camera status and containment timing

The interface includes a camera-status tile and a containment panel with before/current access indicators. An optional feed-metadata source can be configured, but the current agent does not implement the planned local camera-frame HTTP server/relay, and its wire adapter sends `has_feed=false`. The tile itself displays status text, rather than rendering camera image frames.

The containment timer prefers explicit evidence timestamps; otherwise it derives timing from nearby events. The before/current reachability display is inferred from reported device status. These are presentation aids, not independent connectivity probes or a certified enforcement benchmark.

### 9.8 Browser demo mode

Development mode defaults to an in-browser mock API. It includes **Simulate QR attack**, **Device joins**, and **Cloud outage** controls. The QR action is a scripted event sequence; it is not a QR exploit detector or evidence of real network compromise. Mock login accepts arbitrary credentials. Gemini chat/triage controls require the real API and are disabled in mock mode.

Production builds default to the real API. Browser simulation, packet replay with mock enforcement, and real Linux enforcement must be described separately in the demo.

Sources: [dashboard documentation](../web/README.md), [application](../web/src/App.tsx), [device detail](../web/src/components/DeviceDetail.tsx), [issues](../web/src/lib/issues.ts), [activity](../web/src/components/ActivityView.tsx), [camera tile](../web/src/components/CameraCard.tsx), [containment timing](../web/src/lib/incident.ts), [digest](../ml/securiot_ml/digest.py).

## 10. Backend, storage, and delivery reliability

The backend is FastAPI. Caddy serves the built frontend and proxies `/api` to the API. Docker Compose runs those two services; it does not turn the host into a Linux router or automatically launch the live agent.

| API capability | Principal routes |
| --- | --- |
| Health/readiness | `GET /healthz`, `GET /readyz` |
| Login/identity | `POST /auth/login`, `GET /auth/me` |
| Agent telemetry | `POST /ingest` |
| Agent policy/commands | `GET /sync`, `POST /commands/{id}/ack` |
| Dashboard inventory/events | `GET /devices`, `GET /events` |
| Policy | `GET /policy`, `PUT /policy` |
| Manual actions | `POST /actions` |
| Advice/chat | `POST /advisor/chat`, `GET /advisor/triage` |
| Audit/digest | `GET /audit`, `POST /audit/run` |
| Storage status | `GET /storage` |

Dashboard routes use bearer JWT authentication; login passwords are Argon2id-hashed. The judge account is seeded through explicit initialization. Agent routes use an API key. Model/provider keys remain server-side.

Persistent storage uses PostgreSQL/TimescaleDB, described in the deployment docs as Tiger Data. It holds devices, time-series events, commands, policy, audit, users, and migration metadata. The current code requires schema migration 4, which adds `snapshot_at` and the volume event kind.

Ingest deduplicates event UUIDs, preserves immutable events, and rejects a reused UUID with different content. Snapshot freshness uses `snapshot_at`, falling back to `last_seen`. Exact retry payloads are journaled before upload. Commands support idempotency keys and frozen acknowledgements; lost responses do not intentionally repeat Restore. Crash-interrupted commands are marked uncertain/failed for review rather than claimed to have exactly-once hardware execution.

An explicit single-process in-memory SQLite demo store is available. Auto mode can switch to it after connection loss, with learning mode enabled and a visible storage badge. The fallback remains latched until restart, and temporary data is not silently merged into PostgreSQL. Schema/SQL errors do not count as successful fallback. This is a demo availability feature with identity/storage limitations, not transparent persistent high availability.

An optional Cloudflare Quick Tunnel provides a public HTTPS demo URL. The agent can still detect and enforce locally during API/provider outages; remote visibility, new policy, and dashboard commands depend on connectivity. The planned agent-local dashboard/API server is not implemented here.

Sources: [deployment](../deploy/README.md), [telemetry API](../api/telemetry.py), [controls](../api/control.py), [database](../api/db.py), [storage](../api/storage.py), [migration 4](../api/migrations/004_routine.sql), [Compose](../compose.yaml).

## 11. Coverage boundaries and current verification

### 11.1 Unsupported or unproven detection coverage

The current code does not establish general detection of malware families, payload exploits, command-and-control DNS beacons, phishing/QR exploits, ARP reply spoofing, or dedicated single-target UDP/SYN floods. Slow scans may evade the fixed window. The presence of a trained model does not establish coverage for those families.

Other boundaries include incomplete device identity, stale/missing configured facts, cached CVE data, limited alias matching, packet visibility limits, capture overload, and MAC changes. A low score or quiet traffic is not proof of device safety.

### 11.2 Implementation and hardware evidence

| Area | Evidence level |
| --- | --- |
| Rules/model integration | Source and tests exercise actual artifact loading, feature order, cadence, and advisory model behavior |
| Volume baseline and risk expiry | Implemented and covered by focused routine/API tests |
| Vulnerability provenance | Tests cover exact candidate matching, reported facts, admin-port gating, and simulation boundaries |
| API/React container integration | Repository docs report an isolated Docker smoke test with model predictions, ingest, Restore, acknowledgement, and response-loss retries |
| Live decoy capture | Repository docs report real listener/capture testing in an isolated Docker network |
| Linux packet filtering | Repository docs report an isolated nftables lab; hostapd is stubbed in that lab |
| Physical hotspot/Pi | Wi-Fi disconnect/rejoin, actual AP visibility, persistent deployment, and independent Pi attack/normal evaluation remain separate acceptance work |

During this review, a focused existing test selection covering vulnerabilities, routines, response tiers, the trained model, advisor, audit, and digest produced **104 passed and 1 failed**. The failure is in `tests/test_advisor_service.py`: the API's device response includes `snapshot_at`, while the strict `DeviceView` definition in `contract/schemas.json` does not allow it. That is a current contract inconsistency, not a successful validation result. No application code was changed for this document.

The held-out evaluator was rerun successfully; its results appear in section 4.5. This review did not run live attacks, contact Gemini, change firewall/network configuration, or verify the physical demo hardware.

### 11.3 Differences from older documentation to preserve in the presentation

| Earlier wording | Current implementation |
| --- | --- |
| Isolation Forest model | Calibrated histogram gradient-boosting binary scan classifier |
| Cloud-only factor +10 | Implemented weight +5 |
| Baselines/score expiry are future work | Explicit volume calibration and five-minute signal expiry now exist |
| Discovery only at startup | Startup script plus newer opt-in live guest discovery |
| Always progress through a timed response ladder | Strong integrated ARP/decoy signals can request quarantine directly; policy fallback exists |
| Every high score causes isolation | Static risk and advisory model/volume findings do not independently authorize containment |
| Gemini controls containment | Local detector, runtime, policy, and enforcer control it |
| Digest unavailable or necessarily Gemini-generated | Deterministic offline digest is implemented |
| Camera feed/Bluetooth shutdown/power cycling | Feed server and Bluetooth/power-cycle enforcement are not implemented |
| Firmware/CVEs are automatically verified | Static facts are reported; KEV matches are candidates without firmware applicability checks |
| Migration version 3 | Current readiness expects migration 4 |

Some UI text still calls suspicious or restricted devices “infected” or describes attacks with more certainty than the evidence supports. For the presentation, use “suspicious activity,” “candidate vulnerability,” and “agent-reported containment” unless separate evidence establishes a stronger claim.

## 12. Description for the demo narration

> CasaWarden protects smart devices from the network. A local agent observes device traffic and combines fixed detection rules with a trained scan classifier. It assesses reported weaknesses such as default credentials, unsupported products, risky services, and candidate known-exploited vulnerabilities. When strong scan or decoy evidence meets the safety policy, it can isolate the device using Linux firewall and Wi-Fi controls. The dashboard shows what happened, explains the risk, and lets the user request quarantine or restore access. Gemini provides device-specific explanations, hardening suggestions, chat, and a suggested fix order. Local detection and containment continue without Gemini, and the audit distinguishes proposed actions from reported outcomes.

A useful draw.io sequence is:

| Click / scene | Visual focus | Explanation |
| --- | --- | --- |
| 1 | Smart devices on the LAN | Introduce the devices and the problem of limited visibility/support |
| 2 | Router/agent and traffic arrows | Show where packet observation occurs |
| 3 | Inventory and reported device facts | Explain identity, ports, support status, and unknown evidence |
| 4 | Rules and trained model | Show the two complementary scan-detection paths |
| 5 | Decoy destination | Demonstrate the strong signal used for the containment walkthrough |
| 6 | Safety-policy gate | Show learning mode, local arming, protected devices, and timing safeguards |
| 7 | Firewall/Wi-Fi restriction | Show the action reported by the selected mock or Linux backend |
| 8 | Dashboard and Gemini | Explain the finding, next step, and advisory AI boundary |
| 9 | Restore command round trip | Show queue, agent acknowledgement, and recovery grace |
| 10 | Audit history | Show detection, proposed/applied outcome, and user recovery |

Use real measured values from the actual demonstration for timing. Label browser simulation and replay outcomes as simulated. Keep model-only warnings visibly advisory.

## 13. Documentation reviewed

All repository Markdown documents present at review time were read:

| Document | Main contribution |
| --- | --- |
| [Root README](../README.md) | Project intent, headline architecture, initial demo concept |
| [Contract README](../contract/README.md) | Schema, endpoints, telemetry/action semantics, advisor boundaries |
| [Discovery guide](../scripts/STEP2_DISCOVERY.md) | Reviewed startup inventory discovery |
| [Agent README](../agent/README.md) | Agent modes, packet processing, safeguards, test/deployment limits |
| [Integration](../agent/INTEGRATION.md) | Component boundaries and local/cloud flow |
| [Cloud runner](../agent/CLOUD_RUNNER.md) | Ingest, sync, acknowledgement, retry journals |
| [Model handoff](../agent/MODEL_HANDOFF.md) | Actual model integration, cadence, provenance, evaluation |
| [Threat coverage](../agent/THREAT_COVERAGE.md) | Supported signals, vulnerability evidence, known gaps |
| [Live decoys](../agent/LIVE_DECOYS.md) | Live capture and decoy implementation/testing |
| [Linux enforcement](../agent/LINUX_ENFORCEMENT.md) | Real firewall/Wi-Fi controls, recovery, hardware acceptance |
| [Fixture guide](../agent/fixtures/README.md) | Synthetic packet provenance and expected outcomes |
| [Web README](../web/README.md) | Dashboard, mock mode, API integration, controls |
| [Deployment guide](../deploy/README.md) | API/frontend hosting, authentication, Gemini, storage, audit |

Code references throughout this document identify the implementation used to resolve stale or conflicting documentation.
