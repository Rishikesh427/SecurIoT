# Threat, identity and vulnerability coverage

Reviewed at `332f573` (November 15, 2026). Generated packet tests verify behavior,
not general precision/recall, every CICIoT family, or a device's freedom from malware.
See [recent verification/gaps](../docs/RECENT_CHANGES.md#verification-and-known-gaps).

| Evidence | Current integrated response |
| --- | --- |
| Fast ARP sweep | Rule threshold plus at least eight distinct ARP targets can authorize containment |
| Repeated gateway resolution | Quantity without multi-host evidence remains a warning |
| TCP SYN host/port scan | Distinct outgoing IP/port targets; advisory |
| Trained binary scan score | Minimum signal, adjacent seconds and cooldown gates; advisory `scan_targets` |
| Explicit decoy SYN | Strong finding; eligible under automatic safeguards |
| Volume deviation | Explicit calibrated ten-second window baseline; advisory `volume` |
| New discovery | Inventory/event/identity hints; no compromise verdict |
| AP departure/return | Presence status only; no threat verdict |

Retransmissions and SYN-ACK/ACK/FIN/RST do not inflate outgoing unique SYN target
counts. Inbound/outbound captured bytes are counted separately; the trained scan
model uses outgoing-frame features. The fixed-window routine uses both directions.

## Baselines and risk expiry

Calibration is requested locally via `python -m securiot_agent.routine --help`.
It needs 30 complete clean ten-second windows in learning mode. Restricted,
signaling/tainted and incomplete windows are excluded. The baseline is frozen
until recalibration; detection uses `max(std,1024 bytes)` and z >= 4. A volume
signal does not independently authorize containment. Active behavioral risk
expires 300 seconds after the latest signal; this does not release restrictions.

## Passive identity and service evidence

OUI/DHCP/hostname/example-MAC hints produce labeled inferred type/vendor data.
Private/randomized MACs limit vendor lookup; hints are not authenticated identity.
Observed listening ports come from the device's own SYN-ACK source port, not
ports it scans. Passive traffic observations do not prove vulnerability or safe
configuration. Presence does not verify identity, firmware, password or compromise.

Reported facts, inferred observations and simulated personas remain distinct.
The assessor can flag reported/observed risky services; HTTP 80/8080 alone does
not prove an admin interface. Admin points require explicit admin-port facts.
Inferred vendor/type is not promoted to confirmed firmware/credential or catalog
applicability evidence. Missing facts stay unknown.

Catalog candidates require normalized exact vendor AND product matching. A name
match is a candidate (+15), not verified affected firmware (+30). Simulated personas
cannot create a confirmed real CVE. Aliases/cache age/limited catalog coverage
remain constraints, and no match is not proof of safety. The heuristic behavioral
strength is not an infection probability.

Grounded Gemini public research reports vendor documentation with sources. It
must distinguish published firmware/default policy from the device's installed
firmware/current password; it does not update measured facts, risk or enforcement.
Research failure, absent identity and provider budget exhaustion are shown as
unknown/unavailable, not a clean bill of health.

```bash
agent/.venv/bin/python -m securiot_agent.vulnerabilities --devices contract/fixtures.json
```

This inspects configured/synthetic facts; it sends no device login or exploit.

## Known limits and acceptance

Slow scans can evade a ten-second window. There is no integrated general malware
family/payload classifier, dedicated single-target UDP/SYN flood detector,
ARP-reply binding-consistency detector, DNS beacon/C2 classifier, or QR exploit
analysis. A legitimate scanner can resemble a malicious sweep. Capture overload,
missed traffic, changing MACs and inaccurate reported facts reduce reliability.

PR #18 notes repeated ARP alerts/event flooding and resulting capture/upload load.
The review does not establish that issue as fixed; do not promise one event per
attack or guaranteed sub-second containment. See the current test failures in
[RECENT_CHANGES.md](../docs/RECENT_CHANGES.md).

Evaluate frozen features/rules/model on independently labeled sessions/devices,
with false alerts per device-hour, episode recall, false quarantines and latency.
The saved UNSW/synthetic-sweep evaluation is not real Pi attack accuracy. Physical
Wi-Fi isolation/rejoin and persistent database/provider operation require separate
checks. Learning mode, explicit protection, manual overrides and Restore grace
have different semantics described in [LINUX_ENFORCEMENT.md](LINUX_ENFORCEMENT.md).

PR #20 adds nl80211 station removal for NetworkManager hotspots. It does not
provide an AP admission deny list; clients can reassociate before the next
roughly one-second re-kick. Hardware validation must cover same-SSID forwarding.
