# Device discovery: reviewed snapshots and live inventory

Reviewed at `332f573` (November 15, 2026). There are two distinct tools; the
startup snapshot is not the live agent's input anymore.

## Reviewed snapshot utility

On the Linux router, from the repository root:

```bash
python3 scripts/discover_devices.py --interface wlan0 --cidr 10.42.0.0/24 --leases /var/lib/misc/dnsmasq.leases --out devices.discovered.json
```

Use the actual interface/subnet/lease path. Omit `--leases` without dnsmasq.
Review the output before saving it as `devices.reviewed.json`. New records default
to `protected=true`. DHCP names are unverified labels; lease/cache entries do not
prove presence. This IPv4-only snapshot tool sends no active discovery probes.

For a later snapshot, use `--base devices.reviewed.json --out devices.next.json`.
Reviewed names/protection/risk facts are retained; conflicting addresses stop
generation. Keep real inventories and private device data out of Git.

```bash
python3 scripts/test_discover_devices.py
```

## Current live path

The public `--live` CLI requires Linux enforcement and
`SECURIOT_DISCOVERY_CONFIG`; it rejects `--devices` and mock enforcement.
Copy `agent/discovery.demo.example.json`, set the actual AP/subnet/lease path,
and follow [Linux enforcement setup](../agent/LINUX_ENFORCEMENT.md).
Install `agent[cloud,replay,discovery]` plus model dependencies.

Live discovery hot-adds source MAC/IPs, DHCP/neighbor hints and AP stations to the
inventory, collector and enforcer, up to 20 devices. It excludes the AP's MAC,
configured exclusions, multicast/invalid addresses and conflicting IP claims.
`protect_guests` defaults false in the example: discovery is not an approval or
a security verdict. Keep controller MACs explicitly protected.

Passive identity uses observed server-side traffic, DHCP name/vendor class and
netaddr's offline OUI registry. Hints stay labeled as inferred; private MACs and
unknown models remain limited. Identity does not establish firmware or credentials.

Presence watches `iw event` and polls station state: announced leave has a
3-second grace, silent absence 15 seconds after observation, and association or
source traffic can bring a client back. Quiet associated clients also receive
an initial seen time so they can appear without sending a captured packet. Unknown station state does not mark
clients offline. Presence changes request an immediate upload; last packet time
and snapshot revision are distinct. Cache files are `discovered-devices.json`
and `presence.json` in the agent state directory. Restrictions remain separately
journaled and take precedence over offline display.
