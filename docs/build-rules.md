## Coldguardian build: rules for every builder

Project: Coldguardian, a new Cold Stack product. Use a worktree of the private repository. It will be public one day, so never commit private hosts, IPs, topics, usernames or paths from the owner's network.

Read first:
- [docs/north-star.md](north-star.md) (the promises are binding)
- [docs/v1-plan.md](v1-plan.md) (your task row, its done test, repo layout, "Not in v1")
- [docs/research/netguard-audit.md](research/netguard-audit.md) when your task carries over netguard code

Rules:
- Python standard library only, zero runtime dependencies. Nmap is the only external program. No Docker.
- Read-only product: never add code that blocks, fixes or changes anything on the network or a host.
- Do only your task. Nothing from "Not in v1".
- Do not write code comments except where behavior truly cannot be expressed in code.
- Run builds and tests with `offload -- <cmd>` or in CI. Never weaken, skip or delete a test to make it pass.
- CI runs only on the self-hosted Coldbox runner (`runs-on: [self-hosted, coldbox]`), never GitHub-hosted runners.
- Lab tests that need VMs or a network use isolated Coldbox VMs. Never scan the owner's real LAN or any host outside a throwaway lab.
- Open one PR against main. The PR body states: what changed, the done test from the plan and its evidence (commands, real test count), and anything not verified.
- Own your pull request through merge. Watch its checks and reviews, and fix failures and findings. Merge when Coldbox CI is green and no P0 or P1 findings are open.
- When finished, report: PR URL, head commit, test count, done-test evidence, and anything left.

## Coldguardian build: rules for every reviewer

You are reviewing one PR in the private repository, a new Cold Stack product. You are read-only: change no code, push nothing, and do not merge.

Read first:
- [docs/north-star.md](north-star.md) (the promises are binding)
- [docs/v1-plan.md](v1-plan.md) (the PR's task row, its done test, and "Not in v1")

Check:
1. Does it do the task, and is the done test actually proven by the PR's evidence and CI? Read the CI log; do not take the PR body's word for it.
2. Correctness bugs, and security problems: anything that could scan outside the approved scope, run a program other than the allowed ones, write to the network or a host, send data off the box, or let scanned text steer the model.
3. Anything private: the owner's hosts, IPs, topics, usernames or paths. The repo will be public one day.
4. Scope creep (anything from "Not in v1" or from other tasks), new runtime dependencies, Docker, weakened or skipped tests, and code comments that aren't needed.

Use `offload -- <cmd>` if you need to run anything.

Post exactly one comment review: `gh pr review <n> --comment --body-file <file>`. Do not approve or request changes. Give each finding a severity: blocking or non-blocking.

Report back: the verdict ("clean": no blocking findings, or "changes needed"), the list of blocking findings, and the review URL.
