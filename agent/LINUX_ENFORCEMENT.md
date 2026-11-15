# Linux hotspot enforcement, discovery and recovery

Reviewed at `332f573` on November 15, 2026. Use a Linux laptop or Pi as the routed
Wi-Fi AP, with a separate uplink. A Pi acting only as an ordinary Wi-Fi client
cannot enforce the rest of the LAN. See [recent changes/gaps](../docs/RECENT_CHANGES.md).

## Prepare the router

Set up AP-capable Wi-Fi, DHCP, forwarding and internet sharing/NAT first. Both
standalone hostapd and NetworkManager/wpa_supplicant AP control are supported.
This backend does not provision them. Its current preflight requires an unbridged
AP/uplink, Linux/root and supported nftables netdev egress (documented target Linux 5.16+). Existing
flowtables are rejected; hardware/driver bypass and tc redirects need separate
validation. Keep existing routing/NAT/firewall rules intact.

Example hostapd fragments (complete SSID/WPA/country/channel/driver settings too):

```ini
interface=wlan0
ctrl_interface=/run/hostapd
macaddr_acl=0
ap_isolate=0
```

In hostapd mode, matching interface/socket and explicit `macaddr_acl=0` are
required. `ap_isolate=0` permits pre-quarantine phone-to-Pi demo traffic. Quarantine uses a
deny list and deauthentication in addition to firewall drops because same-SSID
traffic may be handled inside the Wi-Fi driver.

Copy `agent/enforcement.example.json` to `/etc/securiot/enforcement.json` and
replace AP/WAN names, hostapd paths and protected controller MACs. At least one
real controller MAC is mandatory; do not use the example address. Router interface
MACs are protected as well. Match the same controller protection in dashboard
Settings so the UI reflects the backend's protection.

Copy `agent/discovery.demo.example.json` to `/etc/securiot/discovery.json`; set
`interface` to the same AP, actual IPv4 CIDR and optional lease path. The current
example has `protect_guests=false` and max_devices 20. Set exclusions intentionally.
Keep these files private/root-owned. Legacy `/etc/securiot` and `/var/lib/securiot`
paths remain supported; a consistently configured `/etc/casawarden` location also
works. The backend journal is bound to its enforcement config identity.

### NetworkManager hotspot alternative

For an AP run by NetworkManager/wpa_supplicant without hostapd, use exactly this
configuration shape instead (replace names/MAC with real values):

```json
{
  "ap_interface": "wlan0",
  "wan_interface": "eth0",
  "wifi_control": "nl80211",
  "protected_macs": ["02:00:00:00:00:02"]
}
```

Do not include hostapd path keys in this variant. Preflight requires `iw` to report
AP mode. Quarantine installs the same nftables drops and removes the station with
`iw ... station del`; the live loop checks roughly once a second and removes
quarantined clients that reassociate. **There is no AP admission deny list in this
mode.** Reassociation and a same-SSID forwarding window may occur before removal;
validate the actual radio/driver. Restore/panic stops owned re-kicks. Hostapd mode
retains its deny-list/deauthentication behavior. The remaining commands apply to
both modes with the appropriate config.

## Install and start

Install hostapd separately if using its standalone control mode; the
NetworkManager/nl80211 variant does not require a hostapd service.

```bash
sudo apt-get install nftables iproute2 iw
python3 -m venv agent/.venv
agent/.venv/bin/python -m pip install -e 'agent[cloud,replay,discovery]' -e ./ml -r ml/requirements-model.txt
```

Set `AGENT_API_KEY` in the shell to match the API without placing it in command
arguments. Configure the files above, then from the repository root:

```bash
export SECURIOT_REAL_ENFORCEMENT=yes
export SECURIOT_DISCOVERY_CONFIG=/etc/securiot/discovery.json
sudo --preserve-env=AGENT_API_KEY,SECURIOT_REAL_ENFORCEMENT,SECURIOT_DISCOVERY_CONFIG \
  agent/.venv/bin/python agent/agent.py --live wlan0 \
  --enforcement linux --enforcement-config /etc/securiot/enforcement.json \
  --state-dir /var/lib/securiot --arm --connect \
  --api-url https://YOUR-API-HOST/api --model-mode required \
  --decoy-ip 10.42.0.50 --decoy-ip 10.42.0.51
```

Substitute your interface, URL/subnet and assigned decoy aliases. Loopback HTTP
is allowed if the API is on this router. Omit `--connect` for local automatic
operation. Do not pass `--devices`: the current public live CLI rejects it and
starts from discovery. It also rejects mock enforcement. Offline replay/simulation
still uses mocks. Existing real restrictions can reload from journals; live
unrestricted inventory is rediscovered rather than seeded from fixture records.

Capture enqueues on a bounded buffer; processing, discovery, policy and actions
have one writer. Overload can drop coverage. Successful live sync is scheduled
at 0.5 seconds, with error backoff up to 30 seconds; presence changes request an
immediate upload. `iw event`/station checks provide 3-second explicit-leave and
15-second silent-absence grace after observation. Absence is not a threat finding.

## Automatic and manual controls

`--arm` plus cloud learning mode off permits automatic containment. Every start
begins learning; protected targets, step toggles, 30-second warmup, 10-second
cooldown and 60-second Restore grace remain automatic safeguards. Switching
learning mode does not release saved restrictions.

Manual Block Internet/Quarantine commands are deliberate overrides: they bypass
automatic learning/arming and timers, including Restore grace. Explicit controller
or cloud/manual protection and disabled steps still prevent them. Default guest
automatic protection is distinct from explicit manual protection. Restore remains
available for recovery and grants automatic grace; it does not repair the client.
Warn is informational and does not invoke this backend.

The dashboard uses `/actions?wait=true`: it queues and waits up to ten seconds
for a sync/ack result, otherwise reports pending. The current direct-loopback
listener class/router URL is not wired into API/live execution. See
[Pi control status](../docs/PI_DIRECT_CONTROL.md); no immediate execution SLA is
established by setting that environment variable.

## Backend and durable state

- `block_wan`: drops outbound routed and return traffic by MAC for IPv4/IPv6,
  keeping local/router access. Traffic must traverse the enforcement host.
- `quarantine`: Ethernet ingress/egress drops, including ARP/IPv6; hostapd deny
  and disconnect, or nl80211 station removal/re-kick upkeep; verification that no associated/authorized station
  remains. hostapd may retain an unauthenticated historical record.
- `restore`: removes owned restrictions/denial and permits client reconnection.
  It neither forces a client to rejoin nor deletes external administrator bans.
- `restore_all`: attempts known confirmed and pending partial recovery, reporting
  failure if not all operations succeed.

Only owned `inet securiot_guard`/`netdev securiot_guard` tables are replaced,
in one nft transaction after validation. Ownership comments guard against replacing
another table. Other rules and external AP denies are preserved.
`enforcement.json` records intent/confirmed effects; partial failure leaves the
last confirmed status with uncertainty evidence. `cloud.json` freezes delivery
and ack results; `state.json` and `routine.json` are separate. Discovery/presence
cache is not an authority to override protected-device configuration. Do not reuse
simulation state for Linux or run two agents against one directory.

## Local panic

Stop the running agent first (the same state directory is process-locked), then:

```bash
sudo agent/.venv/bin/python agent/agent.py --panic --enforcement linux \
  --enforcement-config /etc/securiot/enforcement.json \
  --state-dir /var/lib/securiot
```

Panic uses the enforcement journal rather than a devices file. It clears owned
tables and owned deny/re-kick entries, including pending intents, without flushing global
firewall state. It can clear tables if the AP/hostapd config disappeared. If the
hostapd socket is unavailable, Wi-Fi cleanup remains pending and the command
reports failure; retry after recovering hostapd. Restart without `--arm` while
investigating automatic behavior; explicit manual controls can still request actions.
Keep local keyboard access for initial physical tests. MAC restrictions are not
permanent authentication against a client changing its MAC.

## Verification and hardware checklist

```bash
agent/.venv/bin/python -m pytest agent/tests ml/tests tests -q
agent/.venv/bin/python agent/tools/smoke_firewall.py
```

The isolated lab uses a network-disabled Docker container and child namespaces,
read-only repository mount, no published ports/host network, NET_ADMIN/NET_RAW and
SYS_ADMIN with a relaxed seccomp profile for namespace creation. It tests real
IPv4/IPv6 packets and an established TCP connection, protected controller traffic,
Restore/panic and preservation of another table. IPv6 neighbors are fixed to
separate filtering from multicast discovery; hostapd is stubbed. The container
and its namespaces are removed afterward. This documentation review did not rerun
that hardware-independent lab; historical passes do not validate a radio.

On the real AP check initial peer/WAN access, WAN-only blocking, manual quarantine
without an alert, failed reassociation, unaffected controller, Restore/rejoin,
automatic grace, learning/manual distinction, restart intent, and panic. Include
IPv6, existing connections, phone-to-Pi traffic and capture-overload monitoring.
PR #18 reports some live presence/ingest checks; PR #20 adds nl80211 support
and quiet-client listing. Neither is a complete physical acceptance matrix.
Current local suite failures are in [the review](../docs/RECENT_CHANGES.md#verification-and-known-gaps).
