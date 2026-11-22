# Coldguardian v1 build status

The owner resumed the build on 2026-11-20 and moved it from Orca to T3.

North Star: [north-star.md](north-star.md). Plan: [v1-plan.md](v1-plan.md). Research: [research/](research/). Rules every builder and reviewer gets: [build-rules.md](build-rules.md).

## Who builds what

Sol 6.2 high builds every task. Sonnet 5.5 medium reviews.

Order: Task 1 first. Then 2, 3, 4, 5 and 7 in parallel. Task 6 needs 2 and 5. Tasks 8 and 9 need 3. Task 10 needs 8. Task 11 needs 9 and 10. Task 13 needs 2, 3, 4, 5 and 7. Task 12 is last.

Builders merge their own PRs when Coldbox CI is green and no P0 or P1 findings are open. CI runs only on the self-hosted Coldbox runner.

## Where each task stopped

| Task | PR | State at stop | Review | Open findings |
|---|---|---|---|---|
| 1 Seed | #1 | **Merged** (3e093a8) | Opus: clean | Non-blocking: actions/checkout isn't SHA-pinned. The Coldbox receipt has no JUnit output. |
| 2 Scope detection | #3 | Fix work in progress. WIP commit `34e2c53` (unverified). | Opus: 3 blocking | B1: the size cap applies to IPv4 LAN only, so fc00::/7 and oversized WireGuard ranges get through. B2: Tailscale shared-in and Mullvad exit-node peers are included. B3: an ISP CGNAT segment can be proposed as the LAN. Also: a stopped tailscaled fails all of setup. |
| 3 Quick and deep scans | #6 | Fix work in progress. WIP commit `d675877`, which passed 48 tests in a builder VM before the commit. | Not started | The two-VM lab was replaced by one VM with a network namespace, because Coldbox port isolation blocks two VMs. A real two-VM lab is still needed for Task 12. `ssh-auth-methods` is tagged intrusive by Nmap: it sends one random-username login request. |
| 4 Risky-service rules | #2 | Rule fixtures cover 12 positive and 24 hard-negative cases. | Sol and Sonnet: blocking findings fixed | Task 13 enables the packaged `coldguardian-model-list.nse` in the `-sV` deep scan and connects `rules.check()` to scanning and reporting. |
| 5 Levels | #4 | Fix work in progress. WIP commit `7c35325` (unverified). | Opus: 1 blocking | The coverage filter was removed and a test was rewritten to match. Being fixed: restore the filter and the test, keep paging for a missing or mismatched baseline at medium, and add `Persistent=true` to the timers. |
| 7 Feeds and link check | #5 | Pushed (`033ef19`), CI green, 42 tests. | Opus: stopped partway, nothing posted | Early findings from reading the code. (1) The DNS match pages on shared hosts such as github.com that appear in feed URLs. (2) `check-link` doesn't decode percent-encoding or dot-segments. (3) URLs with a username come back unknown, and feed entries with one are dropped. Not yet checked: the socket-blocked test and the SSH log reader. |
| 6, 8–13 | — | Not started | — | — |

## Loose ends to assign

- Task 13 adds producers for `login_burst`, `peer_change` and `baseline_drift` and wires the rules, levels and feed findings into the scan report. Nothing reads `deep_top_ports` yet.
- Task 7 drops the inherited SSH DNS log reader and picks a free public feed that needs no key and allows local caching.

## Needs owner approval

- A real two-VM lab network on Coldbox, for Task 12.
- The LAN host and approval for the 7-day live run (Task 12).
- Before this repo goes public, run release-check. Check the candidate for private host references.
