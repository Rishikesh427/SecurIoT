# Live capture and TCP decoys

Reviewed at `332f573` (November 15, 2026). The public `--live` CLI now requires
real Linux enforcement and discovery configuration. It rejects mock enforcement
and fixture `--devices`; old two-terminal sniffer examples using those flags are
no longer valid. Use the [Linux runbook](LINUX_ENFORCEMENT.md) for live startup.

The Scapy capture callback feeds live discovery and the shared collector/model/
runtime. Captured Ethernet source MACs provide attribution; a configured IP-to-MAC
mapping is not packet-level identity proof.

## Decoy service

Assign unused decoy IP aliases to the AP first. The listener does not provision
aliases, routing, DHCP or the hotspot. On the router, in a separate terminal:

```bash
sudo agent/.venv/bin/python agent/tools/decoy.py --bind 10.42.0.50 --bind 10.42.0.51 --ports 23 2323 80 445 554 8080
```

Use your actual subnet/assigned addresses. Add `--decoy-ip 10.42.0.50
--decoy-ip 10.42.0.51` to the fully configured live-agent command. Those IPs are
explicit detection destinations; listeners alone do not configure the collector.

The service accepts/closes real TCP connections without collecting credentials,
executing commands or implementing an exploitable Telnet/SMB service. It rejects
wildcard/multicast binds and invalid/duplicate ports, and closes previously opened
listeners if startup later fails. Its JSON log records peer IP/local port. An
optional `--devices FILE` on the **decoy tool** supplies a labeled configured
`mapped_mac`; this is separate from the live agent's prohibition on fixture input.
Unknown peers stay unknown in that mapping.

An outgoing SYN to an explicitly configured decoy can produce `decoy_touch` and
request containment through automatic safeguards. A legitimate inventory scanner
can also touch a decoy; this is suspicious activity, not proof of infection.
Model-only binary scan findings remain advisory.

## Verification

```bash
agent/.venv/bin/python -m pytest agent/tests/test_decoys_live.py -q
agent/.venv/bin/python agent/tools/smoke_decoy_capture.py
```

The Docker lab creates an internal network/two containers and an actual TCP
connection. A real Scapy sniffer observes its Ethernet source MAC, passes the
collector/detector/runtime and requests mock quarantine. It primes warmup and
uses rules mode through test helpers; it is not the current public live CLI.
It removes its own containers/network and does not sniff the host network.

Hostapd and NetworkManager/nl80211 modes have different reassociation behavior;
see the Linux runbook. Real Linux enforcement is separately exercised by `tools/smoke_firewall.py`,
with hostapd stubbed. PR #18 reports live AP presence/ingest checks. Physical radio
visibility, disconnect/denied reassociation/Restore, replay-to-Pi model transfer,
and labeled real attack/normal accuracy still need their own acceptance evidence.
