# Model adapter, live capture, and real decoy services

## What is implemented

1. The adapter passes new packet activity to C's rule detector, not cumulative
   10-second totals. The trained-model path uses C's shared Window on outgoing
   frames and predicts at the training cadence (first outgoing packet per second).
   It selects and validates the saved feature subset/order against estimator metadata.
2. `--live IFACE` uses Scapy to feed the same collector/adapter/runtime as replay.
   Live mode now honors `--model-mode required|auto|rules` and prints model status.
3. `tools/decoy.py` starts real accept-and-close TCP listeners. It never reads
   credentials, executes a command, or implements an exploitable Telnet/SMB service.

Model-only binary scan warnings remain advisory. Decoy/strong ARP signals can
request containment through the existing safeguards. These commands default to
mock enforcement. For the implemented real Linux backend, manual dashboard actions,
and physical acceptance steps, see [LINUX_ENFORCEMENT.md](LINUX_ENFORCEMENT.md).

## Verify on the current Mac with Docker

```bash
agent/.venv/bin/python -m pytest agent/tests ml/tests -q
agent/.venv/bin/python agent/tools/smoke_decoy_capture.py
```

The second command creates an internal Docker network and two test containers.
One opens a real TCP connection to the other's decoy. A real Scapy sniffer on
that container's `eth0` sees the Ethernet source MAC and produces `decoy_touch`
through the collector, detector, and safety/runtime path. The test primes its
clock past warmup and uses rules mode; it verifies real capture/listener plumbing,
not model accuracy. It removes its containers/network afterwards and never sniffs
the host network. The separately tested trained path uses the actual saved model.

## Run on the Linux hotspot later

First configure the AP and assign the unused decoy IP(s) on that interface.
The service does not create aliases or change network configuration for you.
Your devices JSON must contain the actual demo MAC/IP bindings. In two terminals:

```bash
sudo agent/.venv/bin/python agent/tools/decoy.py \
  --bind 10.42.0.50 --bind 10.42.0.51 \
  --ports 23 2323 80 445 554 8080 --devices /path/to/devices.json
```

```bash
sudo agent/.venv/bin/python agent/agent.py --live ap0 \
  --devices /path/to/devices.json --decoy-ip 10.42.0.50 \
  --decoy-ip 10.42.0.51 --arm --model-mode required
```

Default live startup has 30 seconds of warmup. Learning mode applies unless
`--arm` is explicitly supplied. Bind IPs must be assigned unicast addresses;
wildcard/multicast binds and invalid/duplicate ports fail rather than silently
listening elsewhere. Port bind failure closes previously opened listeners.

The server's structured log reports peer IP, local port, and an optional
`mapped_mac` from the configured bindings. It labels that identity source as
`configured_ip_mapping`, never as a directly observed packet MAC. Unknown IPs
remain unknown. The agent's live sniffer supplies actual Ethernet-MAC attribution
and is the source of detection decisions. This prevents stale IP mappings from
being silently presented as packet-level proof.

For offline model replay and actual API/React Docker checks, see MODEL_HANDOFF.md
and CLOUD_RUNNER.md. `--connect` now supports live cloud polling. Native Linux AP
visibility, physical Pi traffic, and real Wi-Fi quarantine remain hardware
acceptance tests; real nftables packet behavior is verified in the isolated lab.
