# Main review: after 9 p.m., November 14

Reviewed on November 15, 2026 at application commit
[`332f573`](https://github.com/Rishikesh427/SecurIoT/commit/332f573).
Cutoff: November 14, 2026, **9 p.m. America/New_York (EST)**, or November 15
02:00 UTC. The pre-cutoff first-parent baseline is `36626e1`.

## Merged PRs

| PR | Merged, EST | Area |
| --- | --- | --- |
| [#16](https://github.com/Rishikesh427/SecurIoT/pull/16) | Nov 14, 9:05 p.m. | Dashboard filters |
| [#17](https://github.com/Rishikesh427/SecurIoT/pull/17) | Nov 14, 11:09 p.m. | UI updates |
| [#18](https://github.com/Rishikesh427/SecurIoT/pull/18) | Nov 15, 12:46 a.m. | Presence/Older Devices and API ingest freeze |
| [#19](https://github.com/Rishikesh427/SecurIoT/pull/19) | Nov 15, 12:57 a.m. | API/agent changes |
| [#20](https://github.com/Rishikesh427/SecurIoT/pull/20) | Nov 15, 1:57 a.m. | NetworkManager enforcement, quiet clients, UI/build fixes |

Also reviewed direct commits and integration merges, including `0a391e2`
(explanation logging/DeviceView), `1f89900` (presence upload timing), `5035036`
(API/agent work), and `0818fe7` (Gemini persistence/telemetry import). PR bodies
were checked against final merged source rather than treated as proof of behavior.

## Documentation changes

Updated the existing guides for live discovery/identity, presence snapshots,
current dashboard navigation/controls, live-only API behavior, migration 6,
Gemini budgets/cache/research, NetworkManager/nl80211 controls, and setup commands. Removed obsolete
fixture-live/mock-browser instructions and claims that unwired features work.
Existing implementation names and private deployment helpers were left unchanged.

## Verification and known gaps

Local checks against this snapshot, with live DB tests disabled and fresh web
lockfile dependencies:

| Check | Result |
| --- | --- |
| Agent + ML + API pytest | 440 passed, 2 failed, 8 skipped |
| Web tests | 65 passed, 1 failed |
| Web production build | Passed (PR #20 restored the missing companion export) |

Existing failures/gaps are documented, not fixed by this documentation-only change:

- Direct-action test fails: the loopback class exists, but API dispatch/live draining
  is not wired. The supported path remains sync/ack with optional API waiting.
- Signup test fails: `/auth/signup` is absent despite invitation/UI scaffolding.
- Browser fixture test expects five devices; current test fixtures return three.

PR #18 reports real presence/ingest checks, but notes that fast-leave/restart
acceptance and repeated ARP event/capture load need attention. This review did
not independently test the radio, real attacks, provider quota or live database.
PR #20 also fixes the stale presence-poll test and idle association uploads.
Historical model/Docker results remain labeled historical; they are not new passes.

Commands used: `python -m pytest agent/tests ml/tests tests -q`, `npm ci`,
`npm test`, and `npm run build` in `web/` (Python used the agent venv). No runtime
source, deployment, secrets or database contents were changed.
