# Coldguardian for agents

Coldguardian is a local, alert-only network scanner. It reports changes and changes nothing.
It needs Linux, Python 3.11+, Nmap and iproute2. No telemetry.

1. Install from the source directory: `python3 -m pip install --no-input .`
2. First command: `coldguardian demo` prints a sample report. It needs no config, scans nothing and writes nothing.
3. Check the setup: `coldguardian status --json` (exit 0 = valid config, 2 = missing or incomplete).
4. Set up only with the network owner's go: `coldguardian setup --json --yes` accepts the detected scope and approves the first baseline. It fails if a configuration already exists.
5. Scan: `coldguardian scan --quick --json`. Use `--deep` only when the owner asks; it probes every device in scope.
6. Tests: `python3 -m unittest discover -s tests -v`.

| Exit code | `scan` / `status` | `setup` |
|---|---|---|
| 0 | clean / valid | `ok` or `declined` |
| 1 | a finding needs review | not used |
| 2 | incomplete coverage or bad config | `incomplete`, `canceled` or `failed` |

Rules:
- Never pass `--yes`, `--approve-baseline`, `approve` or `uninstall` without the user's go.
- Scan only networks the user owns or may scan. Never widen `lan_cidr` or clear `deep_exclusions` yourself.
- Output schemas: `docs/scan.schema.json`, `docs/command-outcome.schema.json`, `docs/check-link.schema.json`.
