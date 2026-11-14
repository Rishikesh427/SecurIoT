# Linux hotspot enforcement and manual dashboard controls

The Windows laptop must be booted into Linux and host the demo Wi-Fi. The Pi is
an ordinary Wi-Fi client, not the router. The agent's Linux backend implements
`block_wan`, `quarantine`, `restore`, and runtime `restore_all`.

## Required topology

Use a routed, unbridged AP interface (example `ap0`) and a separate uplink
(example Ethernet `enp3s0`). Set up hostapd, DHCP, forwarding and internet sharing
first; this backend does not provision the hotspot, routes, or NAT. Use a Wi-Fi
adapter with AP support. Linux 5.16+ with nftables supporting netdev egress is
required; Ubuntu 24.04 or a newer suitable Linux system is a practical target.
The backend checks the actual rules with `nft -c` before installation.

Use a dedicated, single-BSS hostapd configuration with matching interface/control
socket and an explicit deny-list policy:

```ini
interface=ap0
ctrl_interface=/run/hostapd
macaddr_acl=0
ap_isolate=0
# Also configure your SSID, driver, country, channel and WPA settings.
```

The demo allows phone-to-Pi traffic before quarantine. Do not enable flowtable
acceleration on this router: it can bypass the forwarding path. The preflight
rejects existing nftables flowtables and bridged AP/uplink interfaces. External
network managers, hardware forwarding, tc redirects, and changes to the AP after
startup need separate validation. Keep internet sharing's existing firewall/NAT
rules in place; SecurIoT adds only its own restrictions.

## Configuration

Copy `agent/enforcement.example.json` to `/etc/securiot/enforcement.json` and
replace the interface names, hostapd paths, and controller MAC with actual values.
At least one controller MAC is mandatory. The backend also protects the router's
own interface MACs and locally configured protected devices. Configure the same
controller protection in dashboard Settings so the UI reflects it.

Create `/etc/securiot/devices.json` with actual, stable demo MAC/IP bindings:

```json
{"devices":[
  {"mac":"02:00:00:00:00:20","ip":"10.42.0.20","name":"Demo Pi","simulated":false},
  {"mac":"02:00:00:00:00:02","ip":"10.42.0.2","name":"Controller","protected":true,"simulated":false}
]}
```

These are examples: replace both MACs/IPs, reserve the addresses, and account for
Wi-Fi private/randomized MACs. Real enforcement refuses generated persona devices
and requires explicit `simulated:false`. Unknown devices are not automatically
registered. Protect the root-owned configuration files against untrusted edits.

Install agent/C inference dependencies in the Linux virtual environment:

```bash
sudo apt-get install nftables hostapd iproute2
python3 -m venv agent/.venv
agent/.venv/bin/python -m pip install -e 'agent[cloud,replay]' -e ./ml -r ml/requirements-model.txt
```

## Start live capture, real enforcement, and dashboard command polling

Set `AGENT_API_KEY` in the shell to match your existing API configuration without
putting the key in a command-line argument. Use the API's HTTPS URL, or loopback
HTTP when the API is on this laptop. Then:

```bash
export SECURIOT_REAL_ENFORCEMENT=yes
sudo --preserve-env=AGENT_API_KEY,SECURIOT_REAL_ENFORCEMENT \
  agent/.venv/bin/python agent/agent.py --live ap0 \
  --devices /etc/securiot/devices.json \
  --enforcement linux --enforcement-config /etc/securiot/enforcement.json \
  --state-dir /var/lib/securiot --arm --connect \
  --api-url https://YOUR-API-HOST/api --model-mode required \
  --decoy-ip 10.42.0.50 --decoy-ip 10.42.0.51
```

Add the decoy aliases/listeners separately using LIVE_DECOYS.md. Capture and
command polling use one runtime writer; capture continues to enqueue while bounded
HTTP calls run. Queue overflow is reported and means detection coverage was lost.
`--connect` now works with live capture as well as replay. Omit it for local-only
automatic enforcement. Replay and simulation cannot select the Linux backend.

`--arm` is local permission to act. Dashboard Settings must also enable automatic
protection (cloud learning mode off). Restarting without `--arm` prevents new
containment. Existing saved restrictions are reconciled even in learning mode;
changing learning mode does not release already quarantined devices.

## Manual quarantine / unquarantine

Open a device in the dashboard and select **Quarantine** or **Restore access**.
No detector finding is required. The authenticated API queues the command; the
live agent polls every two seconds and acknowledges its actual outcome. The UI
shows pending until acknowledgement and continues to show the last reported
status. Failures appear in the acknowledgement/audit outcome. An offline agent
leaves the request pending; queueing alone never means isolation succeeded.

Manual quarantine bypasses automatic warmup, cooldown and restore grace. Local
arming, learning mode, protected-device checks and enabled policy steps still
apply. Restore works while unarmed and establishes at least 60 seconds of grace
against automatic containment; a subsequent manual quarantine can override that
grace. Restore all also attempts recovery of known partially applied restrictions.

## Enforcement and recovery behavior

- WAN blocking drops outbound forwarding and return traffic by MAC for IPv4/IPv6.
  It leaves local/router access available. Routed traffic must traverse this host.
- Quarantine filters ingress/egress Ethernet traffic (including ARP and IPv6), adds
  a hostapd deny entry, disconnects the station if present, and verifies denial
  plus absence of an associated/authorized station (a historical station record
  may remain after deauthentication). AP admission control addresses same-SSID
  traffic that may be forwarded inside the Wi-Fi driver.
- Restore removes our firewall restriction and our Wi-Fi denial. It permits
  reconnection; it does not force a client to reconnect or remove infection.
- Rules replace only `inet securiot_guard` and `netdev securiot_guard`, in one
  nftables transaction. Ownership comments are checked. Other tables and external
  AP deny entries are preserved; an external ban cannot be claimed as restored.
- A durable intent/confirmed journal survives failures/restarts. Partial failures
  are reported as failures and retain the last confirmed device status plus
  uncertainty evidence. A failed command may have applied some restrictions:
  retry Restore, Restore all, or panic. Restart reconciles pending intent before
  publishing restriction status. Do not reuse replay state for Linux enforcement.
- A process lock prevents two agents or panic from editing the same state at once.

For local recovery, **stop the running agent first**, then use the same config and
state directory:

```bash
sudo agent/.venv/bin/python agent/agent.py --panic --enforcement linux \
  --enforcement-config /etc/securiot/enforcement.json \
  --state-dir /var/lib/securiot
```

Panic clears our tables and owned Wi-Fi deny entries, including pending intents.
It uses the enforcement journal rather than the devices file and can clear the
firewall even when the AP/hostapd config has disappeared. If hostapd is
unavailable, Wi-Fi deny cleanup remains pending and the command reports failure;
retry when its socket is available. It never flushes the global ruleset. Restart
without `--arm` while investigating. Keep local keyboard access for initial tests.
MAC-based containment is a demo mechanism; a client that changes its MAC needs
fresh identification and is not permanently authenticated by this scheme.

## Tests and physical acceptance

```bash
agent/.venv/bin/python -m pytest agent/tests ml/tests -q
npm --prefix web test
npm --prefix web run build
agent/.venv/bin/python agent/tools/smoke_firewall.py
```

The Docker lab uses a network-disabled container with child namespaces and real
nftables packets, including an already-established TCP connection. IPv6 neighbors
are fixed in this lab to separate filtering from multicast discovery timing. NET_ADMIN/NET_RAW control only its virtual links; SYS_ADMIN and
its relaxed seccomp profile permit child namespaces. It mounts the repo read-only,
uses no host networking or ports, and removes the container afterward. hostapd is
stubbed in this lab: it verifies actual IPv4/IPv6 firewall behavior, not a radio.

On the physical hotspot, verify Pi internet/local connectivity, WAN-only blocking,
manual quarantine before any alert, inability to reconnect, unaffected controller,
Restore/rejoin, automatic restore grace, persistence through agent restart, and
panic recovery. Check both IPv4 and IPv6, an already open connection, and
phone-to-Pi traffic. Those hardware properties cannot be proven on this Mac.
