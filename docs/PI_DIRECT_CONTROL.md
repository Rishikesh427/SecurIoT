# Raspberry Pi control: current integration status

Reviewed at `332f573` on November 15, 2026, including PRs #19–20. The Linux router
may be a Raspberry Pi or a laptop booted into Linux. It must host the routed,
unbridged Wi-Fi AP with nftables and either hostapd or NetworkManager/nl80211. An ordinary Pi client cannot isolate
other clients through a firewall on itself.

## Supported path

Configure discovery and real enforcement using the [Linux runbook](../agent/LINUX_ENFORCEMENT.md).
Live CLI discovery starts without a fixture inventory. Newly discovered guests
are registered with the collector/enforcer; configured controller MACs retain
protection. Manual actions can bypass automatic learning/timing gates, while
explicit target protection and disabled steps remain enforced.

The tracked path is:

1. The authenticated dashboard calls `POST /actions?wait=true` with a durable
   UUID Idempotency-Key.
2. The API creates the pending command and audit row. It can wait up to ten
   seconds for a terminal command result; otherwise it returns pending.
3. Live agent sync fetches authoritative policy/commands, applies the action on
   its single runtime writer, journals the result and sends an acknowledgement.
4. The API/dashboard reports applied or failed from that result. Lost responses
   reuse journaled acknowledgements rather than repeating the same command UUID.

Normal live sync is scheduled every 0.5 seconds; API errors cause bounded
backoff up to 30 seconds. Packet handling, enforcement and network delays mean
this is not a response-time guarantee. Offline agents leave requests pending.
Warn is informational; Block Internet is WAN filtering; Quarantine also denies
Wi-Fi access; Restore removes only owned restrictions.

## Direct listener exists but is not wired

`agent/securiot_agent/direct_control.py` defines an authenticated, loopback-only
`DirectControl` listener, default port 18081. It validates command/policy payloads
and exposes `drain()` so a runtime writer can fetch current sync and return a
journaled result. Its unit tests do not establish end-to-end deployment.

At this revision, neither `run_live` nor `CloudLoop` constructs/drains this
listener, and the API does not dispatch to `SECURIOT_ROUTER_URL`. Compose passes
that variable, but setting it or `SECURIOT_DIRECT_CONTROL=1` alone does not activate
an immediate route. The direct-action integration test currently fails.
Do not expose port 18081 or describe an SSH forwarding command as sufficient to
activate this path. A separate implementation change is needed.

The locally ignored `safe_deploy.sh` and private deployment state are not a
versioned deployment contract. Public instructions must remain usable without
copying a teammate's private helper or credentials.

## Accounts and physical acceptance

Use an existing provisioned judge/admin account. `SIGNUP_INVITE_CODE` and signup
UI/tests exist, but `/auth/signup` currently returns 404; there is no working
invitation registration flow in the tracked API.

On the real AP, verify peer/WAN access before restriction, WAN-only blocking,
quarantine, hostapd denied reassociation or nl80211 re-kick behavior, unaffected
controller, Restore/rejoin, and
panic recovery. Check IPv4/IPv6 and an already open connection. Listener/mock
unit tests and API acknowledgements cannot independently verify the radio effects.

NetworkManager/nl80211 quarantine has no admission deny list: firewall drops
remain, and the live loop re-kicks reassociated clients roughly once per second.
Hostapd mode uses an actual deny list. Test the radio behavior for the selected mode.
