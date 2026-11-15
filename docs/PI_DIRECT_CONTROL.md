# Immediate Raspberry Pi controls

The Pi must be the routed Wi-Fi access point, running hostapd and nftables.
Quarantine uses the existing Linux backend: ingress/egress drops plus a hostapd
deny entry and deauthentication. WAN blocking keeps local access and drops
internet forwarding. Restore removes CasaWarden-owned restrictions.

On the Pi, create `/etc/casawarden/enforcement.json` using
`agent/enforcement.example.json`. Set the actual AP and WAN interface names,
hostapd paths, and the controller's real MAC in `protected_macs`. The backend
checks these settings, rejects bridges/offloaded flow tables, and fails visibly
if it cannot confirm an operation. Do not use the example MAC on real hardware.

Update both checkouts. The local `safe_deploy.sh` now starts the Pi agent with
`--arm --enforcement linux --enforcement-config /etc/casawarden/enforcement.json`
and `SECURIOT_DIRECT_CONTROL=1`. It forwards port 18081 to the Pi's loopback
control listener and sets `SECURIOT_ROUTER_URL=http://host.docker.internal:18081`
for the Mac API container. The endpoint authenticates with `AGENT_API_KEY`.
The launcher is locally ignored by Git; copy its updated version separately.
Newly discovered demo guests are actionable; configured controller MACs remain
protected. Enable the response policy with the dashboard's Arm button.

Manual commands wake the same runtime writer immediately, fetch current policy,
execute the firewall operation, and return its result in the original request.
The audit entry becomes applied only after execution. Requests retain durable
IDs: a lost connection leaves an uncertain/pending result that regular sync can
reconcile without executing the same command twice. No second acknowledgement
round trip is needed for the UI to show a returned success.

Verify on the demo network: before quarantine, reach a peer from the target;
after quarantine, verify peer and WAN traffic fail and the station cannot
reassociate. Restore and verify both return. For WAN block, verify internet
fails while peer access still works. Check the audit outcome for each action.
These physical effects cannot be established by browser mock tests.

The browser demo has five simulated devices; its operations never alter the
physical router. Notifications alone remain informational. The manual
Warn / Block Internet control performs WAN blocking.

## Account invitations

Set a random `SIGNUP_INVITE_CODE` of at least 16 characters in `api/.env` to
enable sign up. Share it only with people permitted to control this router.
New accounts require passwords of at least 16 characters. Without a configured
code, registration is disabled and login continues to work. Memory-mode
accounts are temporary; PostgreSQL accounts persist.
