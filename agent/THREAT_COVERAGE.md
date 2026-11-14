# Threat and vulnerability coverage

The test matrix uses generated packets and fictitious catalog rows. Passing it
checks implementation behavior; it does not establish real-world precision,
recall, or detection of every CICIoT/UNSW attack family. Unsupported-case tests
explicitly preserve known blind spots rather than count those attacks as detected.

| Signal/case | Current result and checks |
| --- | --- |
| Fast ARP sweeps | C detects the count threshold; the agent additionally requires at least 8 distinct ARP targets before automatic containment |
| Repeated gateway resolution | May produce an ARP warning, but does not auto-quarantine based on quantity alone |
| Host and port SYN scans | Distinct targets counted; supporting warning rather than automatic quarantine |
| Retransmissions, SYN-ACK, ACK, FIN/RST | Do not inflate distinct outgoing SYN targets |
| Explicit TCP decoy touch | A single attempt to a configured decoy is eligible, subject to policy; use `--decoy-ip` |
| Protected devices | Suspicious activity remains visible; automatic restrictions are prevented |
| Learning, warmup, cooldown, Restore grace | Existing guards are tested with the real C integration and mock enforcement |
| Volume deviations | Feature-level C baseline tests only; automatic baseline loading remains disabled until byte-interval units are agreed |
| Slow scans | Can evade the current 10-second window; explicitly a known gap |
| UDP/SYN floods to one target | No dedicated flood detector connected; explicitly unsupported |
| ARP spoofing via replies | No binding-consistency detector yet; explicitly unsupported |
| DNS beacons, payload attacks, malware family classification | Query collection isn't a beacon/exploit classifier; unsupported by current rules |

A legitimate inventory tool sweeping many hosts can look like a malicious sweep
with these features. Configure trusted/protected devices and measure false alarms
on real normal recordings before relying on automatic containment. The threshold
of 8 distinct ARP targets is an explicit local heuristic, not a calibrated claim.

## Vulnerability evidence

`vulnerabilities.py` uses C's score weights but constrains the supplied evidence:

- Reported ports get service-review flags, not confirmed exploit claims. A destination
  port that a device probes is never turned into an open service on that device.
- HTTP 80/8080 alone doesn't establish an admin interface; admin-port points require
  explicit `admin_ports` facts, a subset of reported `ports`.
- Credential/EOL/cloud-only facts are labeled reported or simulated. This build
  performs no active login attempt, device scan, or firmware verification.
- Catalog candidates require normalized exact vendor AND product names; loose
  substring matches don't earn KEV points. Alias/model-family coverage is limited.
- A name match remains a candidate (+15), never confirmed affected firmware (+30).
  A firmware/config applicability evaluator still needs to be implemented.
- Simulated personas retain a simulation label and cannot create confirmed CVEs.
- Missing facts remain unknown, catalog version/age is exposed, malformed CVE IDs
  are excluded, and no match is never presented as proof the device is safe.
- The previous "100% confidence" wording is replaced with behavioral signal strength;
  the heuristic isn't a calibrated infection probability.

Review configured facts without network probes:

```bash
agent/.venv/bin/python -m securiot_agent.vulnerabilities --devices contract/fixtures.json
```

The schema of a candidate CVE and its actual applicability are different concerns;
see [NVD applicability statements](https://nvd.nist.gov/vuln/Vulnerability-Detail-Pages).
The cache is a subset of known exploited vulnerabilities, not a complete list of
all possible weaknesses. See [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).

## Next evidence needed

Evaluate frozen rules/model and preprocessing on independently labeled attack and
normal captures. Separate capture sessions/devices between tuning and final tests.
Report attack-episode recall, false alerts per device-hour, false quarantines, and
latency. Real Pi visibility, Wi-Fi disconnection/restore, actual model transfer,
and production network/database behavior remain separate tests.


## Arrived-model update

The trained binary scan model is connected; see [MODEL_HANDOFF.md](MODEL_HANDOFF.md).
It adds advisory scan-like evidence, not a malware-family classifier. The broad
matrix still deliberately runs in rules mode so baseline safety/coverage results
aren't silently changed by artifact updates. `test_trained_model.py` separately
checks the real artifact and its integration. Unsupported-family gaps above remain;
the presence of a model is not proof those families are now detected.
