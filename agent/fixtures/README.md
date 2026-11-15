# CasaWarden generated packet fixtures

Reviewed at `332f573` (November 15, 2026). Legacy names keep replay/tests compatible.
These files are synthetic Ethernet frames generated locally, not recordings of
real devices or attacks. Generating/replaying them does not transmit packets or
execute real firewall commands.

| Capture | Expected integrated behavior |
| --- | --- |
| `normal.pcap` | DNS/reply traffic and repeated SYNs to one target; no scan finding |
| `scan.pcap` | Advisory target-scan evidence; preview can propose mock containment |
| `arp_scan.pcap` | Multi-host ARP threshold; eligible for mock containment after safeguards |
| `slow_targets.pcap` | Targets spread beyond the window; may evade the detector |
| `protected_arp.pcap` | Suspicious activity remains observable; protected-device action is blocked |

The captures include startup/warmup timing. `devices.json` supplies the synthetic
camera and protected controller. MAC/IP/DNS/persona values are fixture facts,
not verified hardware. Repeated ARP events may occur once a rule threshold stays
crossed; do not infer one finding per capture from the model's separate cooldown.

```bash
agent/.venv/bin/python agent/tools/make_replay_fixtures.py
agent/.venv/bin/python agent/agent.py --replay agent/fixtures/arp_scan.pcap --arm
```

Scapy builds/reads these files. The public live agent rejects `--devices` and
starts with real discovery; the normal API rejects simulated telemetry. Fixture
modules retained in `web/src/mock/` are test helpers and are not a browser demo
mode (`USE_MOCK=false`). See [agent modes](../README.md) and
[current verification](../../docs/RECENT_CHANGES.md).
