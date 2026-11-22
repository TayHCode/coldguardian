# Coldguardian

Coldguardian is a local, alert-only network scanner for your home lab. It
discovers devices on a configured LAN, checks TCP ports, and reports changes
against a baseline you approve. It also summarizes configured DNS and Linux
authentication logs. It leaves network settings and monitored devices unchanged.

## Install and run

Use Linux with Python 3.11 or newer, Python's `venv` and `pip`, Nmap,
and iproute2 (the `ip` command). Building from source requires setuptools
77 or newer, which pip normally fetches during installation.

From the source directory, create and activate a virtual environment.

```sh
python3 -m venv "$HOME/.venvs/coldguardian"
. "$HOME/.venvs/coldguardian/bin/activate"
```

Install Coldguardian and check that the CLI starts.

```sh
python3 -m pip install --no-input .
coldguardian --help
```

Run `coldguardian setup` as your regular user. Review the proposed LAN and
any overlay scope before you approve it. Scan only devices and networks
you own or have permission to scan. Review the first quick-scan report
before approving the scanner host's baseline. The model and ntfy are optional.

Run `coldguardian scan --quick` for a quick scan or `coldguardian scan --deep`
to inventory the approved network scope. Run `coldguardian --approve-baseline`
to approve a later complete scan.

Append `timer` to the level during setup, for example `medium timer`, to
enable scheduling. This requires a running systemd user manager for your
account and a host that supports the user service's mount and user-namespace
sandbox. Use manual scans on hosts without that support.

### Uninstall

Back up your configuration and any reports or approvals you want to keep.
`coldguardian uninstall` permanently removes the following:

- The setup-managed `coldguardian-quick` and `coldguardian-deep` user timers and
  services in `$XDG_CONFIG_HOME/systemd/user` (default `~/.config/systemd/user`).
  Uninstall stops the units and clears timer enablement links and persistent
  timer timestamps. If the units exist, uninstall needs the running systemd
  user manager.
- `~/.config/coldguardian/config.json` and its parent directory if empty.
- The entire `~/.local/state/coldguardian` directory, including reports,
  baselines, finding approvals, and cached data stored there.

After removing setup state, run `python3 -m pip uninstall coldguardian` in
the active virtual environment to remove the CLI. If you installed with
pipx, use `pipx uninstall coldguardian`.

## Command output

`setup`, `uninstall`, `feeds update`, and `status` accept `--json`. For example, run
`coldguardian setup --json` to receive one [JSON outcome](docs/command-outcome.schema.json)
on stdout. Setup still asks for confirmation and sends its scan summary to
stderr. The argument parser reports usage errors on stderr.

`coldguardian status --json` validates the local configuration without starting
a scan. It exits 0 for valid configuration and 2 if the file is missing,
unreadable, or invalid. Pass `--config` to check a separate configuration file.

| Status | Exit code | Meaning |
|---|---|---|
| `ok` | 0 | The command completed. |
| `declined` | 0 | Setup ended before writing configuration because scope approval was declined. |
| `incomplete` | 2 | Setup ended without an approved baseline. |
| `canceled` | 2 | Setup or uninstall was interrupted, or setup input ended. |
| `failed` | 2 | The command encountered an error. |

To use a separate configuration, start with `config.example.json` and pass
`--config config.json`.

| | Quick (default, `--quick`) | Deep (`--deep`) |
|---|---|---|
| Hosts | Hosts in `hosts` and the approved baseline | The whole `lan_cidr`, those hosts, and the approved IPv4 overlay scope present in local metadata |
| TCP ports | Ports open in the approved baseline, or `ports` before one exists | `ports`, which defaults to all TCP |
| Service names | No | `nmap -sV` with `ssh-auth-methods`, `http-auth`, `http-title`, `http-server-header` and `http-grep` |

Both profiles report hosts that do not answer as coverage findings. A deep
scan takes minutes and says so when it starts.
It asks each SSH server once, with one made-up username and no password,
which login methods it accepts. The bundled model-list check makes one
unauthenticated request to `/v1/models` and checks the response without following redirects.

New devices and TCP ports stay in the findings until you approve an updated
baseline. Reports also describe gaps such as scan timeouts, unreachable
devices, and unread log data.

## Configuration

| Key | Meaning |
|---|---|
| `lan_cidr` | Private LAN in CIDR notation. IPv4 accepts `/16` through `/30`, or a `/32` for an address in `hosts`. With `/32`, deep scans skip LAN range discovery. IPv6 prefixes must be `/64` or longer. |
| `hosts` | Map of host names to exact private IP addresses. Names can contain letters, digits, dots, underscores, and hyphens. |
| `tailscale_peers` | Optional list of exact Tailscale peer addresses. |
| `wireguard_subnets` | Optional list of WireGuard interface subnets in CIDR notation. IPv4 prefixes must be `/16` or longer and IPv6 prefixes must be `/64` or longer. |
| `local_host` | Optional host name from `hosts` for local DNS and Linux authentication logs. |
| `optional_hosts` | Names from `hosts` with expected downtime. Downtime still appears in reports. |
| `ports` | TCP ports and ranges for deep scans, such as `22,80,8000-8100`. Defaults to `1-65535`, all TCP. |
| `output_dir` | Absolute directory for private reports and state. Defaults to `/var/lib/coldguardian`. |
| `dns_paths`, `auth_paths` | Absolute paths to logs on the scanner. DNS collection is off until you set `dns_paths`. |
| `suspicious_domains` | Optional domains or suffixes to flag in DNS logs. |
| `feed` | Optional source for the local URL and DNS feed cache. |
| `model_url` | Optional URL of a single-model llama.cpp server, such as `http://localhost:8080`. Omit it or use `null` to disable explanations. |
| `ntfy` | Object with `server` and `topic`, or `null` to disable notifications. |

Configured scope is limited to RFC 1918, CGNAT (`100.64.0.0/10`), and IPv6 ULA
(`fc00::/7`). Automatic LAN detection considers RFC 1918 and IPv6 ULA ranges.
Deep scans use exact addresses from `tailscale_peers` that appear in the local
Tailscale peer list. Detection skips shared and provider-owned peers. Deep scans
also discover hosts where `wireguard_subnets` overlap local WireGuard interface
subnets. Scope detection recognizes interface names that start with `wg` when
`ip` supplies no link kind. Scanning supports IPv4. Reports identify approved
peers that could not be reached and flag gaps in available WireGuard scope.

To read DNS logs, set `local_host` and list the local AdGuard Home query log
or Pi-hole dnsmasq log in `dns_paths`. Give the scanner account read access
to those files. Each scan reads complete lines in the most recent 1 MiB of
each DNS file. A matching query can appear in successive reports while it
remains in that window.
If your configuration uses `dns_hosts`, replace that entry with
`local_host` and `dns_paths` for the logs on the scanner.

The model URL must use HTTP or HTTPS and point to a loopback or private IP.
Scans and setup leave the model idle. Run `coldguardian explain <finding-id>`
to send one finding's allowlisted observations to the local model.

Copy `finding_id` from `coldguardian scan --json`. In Markdown, join the report's
timestamp and the finding's evidence ID with a colon. A bare evidence ID such
as `E2` selects the latest saved scan.

Run `coldguardian approve <finding-id> --reason "Expected device service"` to
record an approval for a finding in the latest scan. The baseline stores the
reason and UTC timestamp. The exact finding still appears in reports, and
subsequent scans suppress its repeat notifications.

Both commands accept `--json` and include `status` and `exit_code`. For explain,
0 means an informational finding, 1 means a finding that needs attention, and
2 means incomplete evidence or an unavailable explanation. The model label
does not decide the exit code. For approve, 0 means saved, 1 means already
approved, and 2 means the command could not save an approval.

### Default local model

The default for configured explanations is Qwen3.5-27B Q4_K_M. Use llama.cpp
build `b12359` (`b1b770d90`) and verify the GGUF SHA-256 against the
LFS object ID on the pinned model page.
[Pinned GGUF](https://huggingface.co/gguf/Qwen3.5-27B-GGUF/blob/5a8fa4f/qwen3.5-27b-Q4_K_M.gguf)

```powershell
llama-server --model qwen3.5-27b-Q4_K_M.gguf --alias Qwen3.5-27B-Q4_K_M `
  --host ([System.Net.IPAddress]::Loopback.ToString()) --port 8080 --device CUDA0 --gpu-layers all `
  --ctx-size 16384 --parallel 1 --jinja --reasoning off
```

For a scanner on the same machine, set `model_url` to `http://localhost:8080`.

## Check links and DNS queries

Use the public TweetFeed weekly CSV. It is free and requires no API key.
Section 7 releases the feed data under CC0 1.0, which allows local caching.
Treat matches as community-reported indicators. [TweetFeed terms](https://tweetfeed.live/tos/)

Add this entry to your configuration and run `feeds update` to refresh the
local cache.

```json
"feed": {"url": "https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/week.csv"}
```

To try it offline, use a `feed` object with `path` set to the absolute path
to `tests/fixtures/feeds/tweetfeed.csv`.

```sh
coldguardian feeds update --config config.json
coldguardian check-link 'https://bad.example/sign-in?account=1' --config config.json --json
```

`check-link` reads only the local cache. It compares the URL's scheme, host,
port, path and query. It ignores fragments and userinfo. It normalizes host
case, trailing dots and default ports, decodes percent-encoded unreserved
characters and resolves path dot-segments. `--json` prints `status` and a
`coverage` array defined by the [link response schema](docs/check-link.schema.json).
Coverage entries have `category` set to `coverage` and a `component` code.

| Status | Exit code | Meaning |
|---|---|---|
| `clean` | 0 | Neither the URL nor its hostname matches an entry in the fresh cache. |
| `bad` | 1 | The URL matches a cached URL or its hostname matches a cached domain. |
| `unknown` | 2 | The URL is unsupported or no fresh cache can confirm a miss. Includes IP literals and punycode hosts. |

The cache adds a `feed_cache_stale` warning after 48 hours. Stale entries can
still produce matches. For DNS queries, the full hostname must match an
explicit TweetFeed `domain` record. Findings record the source, client and
count. DNS names stay local to the lookup.

## Reports and notifications

```sh
coldguardian scan --config config.json --quick --json
coldguardian scan --config config.json --deep --json
```

`scan --json` prints one [versioned scan report](docs/scan.schema.json) to
stdout and writes the normal local report. Each finding names its check and
carries an evidence ID that identifies its row within that report. Port
findings include the observed IP address and ports.

| Exit code | Status | Meaning |
|---|---|---|
| 0 | `clean` | The checks completed without a finding that requires review. |
| 1 | `bad` | A check found something to review. Any coverage gaps are also reported. |
| 2 | `incomplete` | The scan could not establish a result, for example because a required host was unreachable or the baseline was missing. |

The same finding can page at one level and appear only in the digest at
another. Low uses the top 1,000 TCP ports for unrestricted deep scans.
An explicit port restriction takes precedence at every level. A baseline drift
records previously approved ports that a comparable scan no longer sees
open. An unreachable host remains a coverage gap.

A login burst is at least five timestamped SSH failures from one IP within
60 seconds of one another in the newly read portion of an authentication
log. When `tailscale_peers` is configured, peer changes compare the current
Tailscale address list with the last successful observation, or the configured
list on the first run. Observed changes do not expand scan scope.

Reports and state are stored under `output_dir`. The directory uses mode
0700 and the files use mode 0600.

Coldguardian keeps the latest 50 reports by default. Set `report_max_count`
to override the count and `report_max_age_days` to also limit age. Both
settings take positive integers. Each new report trims timestamped Markdown
files and the finding history in `alerts.jsonl`. The count includes the new
report. Coldguardian keeps `latest.md` and the approved baseline.

After an interrupted write, the next report drops an incomplete final JSON
record. If an older writer already appended another report after the damaged
bytes, the damage is now inside the journal. Scans and finding lookups then
exit 2 and identify the corrupt line. The journal stays intact. Preserve a
copy and restore or repair the journal before resuming scans.

A timestamped finding ID lasts as long as its scan remains in the journal.
The scan named in `state.json` stays available for approval across management
or error reports, even when that requires one extra report. A newer scan ends
the previous scan's approval window. Both finding commands report an expired
ID when its scan timestamp falls outside the retained history. Bare IDs such
as `E2` always refer to the latest saved scan.

Low and Medium use the local ARP table to recognize an approved LAN device
that moves to a new IP with the same unique MAC address. A change between
locally administered MAC addresses at the same IP is quiet when the port
list is unchanged and the scan finds no risky service. When neither address
can identify the device, a new IP is still treated as a new device. Approve a
new baseline after a complete scan to store MAC observations for older baselines.

Set an ntfy server and topic in setup to receive notifications. Notifications
include network findings with host names, IP addresses, and port numbers.
Raw logs, DNS names, and usernames stay local. Test delivery with
`coldguardian --test-notification`. For older configurations without an `ntfy`
setting, `COLDGUARDIAN_NTFY_TOPIC_FILE` still sends through ntfy.sh.

Scheduled scans run as oneshot systemd user services with no Linux capabilities.
To keep timers running after logout, enable lingering for your user with
`loginctl enable-linger "$USER"`. This may require administrator permission.

## Limitations

- Coldguardian reports findings for you to review. Scans are read-only and
  leave monitored devices and their data unchanged.
- Network scans cover IPv4 and TCP. Unreachable devices and unreadable logs
  appear as coverage gaps. An empty report cannot establish that a network
  is secure.
- Quick scans revisit configured or baseline hosts and ports. Use a deep
  scan to look for new LAN devices and services. The Low level schedules
  only quick scans.

## Tests

```sh
python3 -m unittest discover -s tests -v
```

## License

Coldguardian is licensed under the MIT License. It started from the public
[homelab-netguard source archive at commit `051d76e`](https://api.github.com/repositories/1431360051/zipball/051d76e68c84a947754d46eb4be0652c6b2167b4).
See [LICENSE](LICENSE) for the original copyright and terms.
