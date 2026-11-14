# Step 2 discovery

Run on the Linux router, from the repository root:

```sh
python3 scripts/discover_devices.py --interface wlan0 --cidr 10.42.0.0/24 --leases /var/lib/misc/dnsmasq.leases --out devices.discovered.json
```

Substitute your actual interface/subnet/lease path. Omit --leases if not using dnsmasq.
Review the output and save as devices.reviewed.json. New devices default to protected=true.
Names from DHCP are unverified labels. No active probes are sent. Lease/cache entries do not prove current presence. IPv4 only; silent devices can be missed. Do not commit device inventories.

For later snapshots, add --base devices.reviewed.json and use --out devices.next.json. Reviewed names, protection and risk facts are preserved. Conflicting addresses stop generation. Previously configured devices are retained.

Install the existing agent dependencies first, then start capture in learning mode:

```sh
sudo .venv/bin/python -m securiot_agent --live wlan0 --devices devices.reviewed.json --model-mode rules --enforcement mock
```

This is startup inventory discovery. It does not hot-add devices to a running collector or Linux enforcer. Stop/review/restart to load a new snapshot. It does not implement risk assessment or Gemini changes.

Test without installing dependencies:

```sh
python3 scripts/test_discover_devices.py
```
