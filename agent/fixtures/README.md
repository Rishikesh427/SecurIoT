# Generated packet fixtures

These files contain **synthetic Ethernet frames created locally**, not recordings
of real devices or attacks. No packets were transmitted to generate them. They
exercise the real packet-file parser and collector while enforcement stays mocked.

| Capture | Expected preview result |
| --- | --- |
| `normal.pcap` | Normal DNS/reply traffic plus repeated SYNs to one target: no scan finding |
| `scan.pcap` | Camera reaches 20 distinct IP/port targets inside 10 seconds: one scan finding |
| `slow_targets.pcap` | The same number of targets spread over 19 seconds: below the window threshold |
| `protected_arp.pcap` | Protected laptop emits 30 ARP requests inside 10 seconds: finding, no restriction |

Each capture starts with normal activity, then crosses the startup warmup period.
`devices.json` identifies the two known, simulated devices and the protected laptop.
MACs, IPs, and DNS names are fixture data, not measured hardware identity.

Regenerate reproducibly from the repository root:

```bash
agent/.venv/bin/python agent/tools/make_replay_fixtures.py
```

Scapy is only used to build/read packet files. Inspect the captures with Wireshark
if you want to see the actual packet headers. There is no live capture or send code.
