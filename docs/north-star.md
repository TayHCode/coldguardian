# Coldguardian — North Star

The owner gave the go-ahead to build on 2026-11-20.

A small local guard for your homelab. It looks, it explains, it tells you. It never touches anything.

The research reports cover [existing tools](research/landscape.md), [upstream behavior](research/netguard-audit.md), and [local models](research/local-models.md).

## 1. What it is

Coldguardian is a small program that runs on one Linux box in your home. When you ask, or on a quiet schedule you choose, it scans your LAN and your Tailscale or WireGuard peers. It finds every device and open port, compares them with what you approved, and flags risky services, known-bad domains and bad links. A local model, on your own GPU or later your CPU, explains each finding in plain words and says whether it looks risky, harmless, or needs you. Plain code decides what gets reported. Nothing leaves your network except the alerts you turn on. It never blocks, fixes or changes anything. It starts from homelab-netguard, which already does the scan, baseline and alert part (netguard-audit.md:5–11).

## 2. Who it is for

- Homelab owners who already use AI agents (Claude Code, Codex and the like) and can run a local model.
- People who want one answer: "is anything bad happening on my network?" That is the low level.
- People who want more: every new device, every new port, every peer change. That is medium or high.

It is not for companies, SOC teams, or networks the user does not own.

## 3. The North Star

Anyone with a homelab can install a guard in one command, forget about it, and trust that if something risky shows up on their network, they will hear about it in words they understand, from a model that never leaves their house.

## 4. Promises

Each promise has a check. If the check fails, the promise is broken.

| # | Promise | How we check it |
|---|---|---|
| 1 | **One command to install, five questions or fewer to set up.** | Fresh Debian/Ubuntu VM. Run the one install line. Count setup questions (≤5). A first quick-scan report exists at the end. |
| 2 | **Nothing runs between scans.** No daemon, no packet capture, no constant polling. | After a scan, `systemctl list-units 'coldguardian*'` shows only an inactive service and, if enabled, a timer. `ps` shows no Coldguardian process. |
| 3 | **Light.** Standard library Python plus Nmap. No Docker. | `pyproject.toml` has zero runtime dependencies. Each report records the scanner's peak RSS. Target: under 150 MB, not counting Nmap or the model (target, not yet measured). |
| 4 | **Quick scan is quick.** | On a /24 with up to 30 known hosts, a quick scan finishes in 60 seconds or less (target, measured in the v1 lab test). |
| 5 | **Deep scan covers everything it was told to, and says what it missed.** LAN, Tailscale peers, WireGuard subnets, all TCP ports, service names. | Lab network with a planted service on an odd port and a peer-only host. Deep scan finds both. An unreachable host shows up as a coverage finding, not silence. Builds on netguard's coverage checks (netguard-audit.md:20–27). |
| 6 | **Code decides alerts.** Hard threats always page under the opt-in tier rules. Only borderline household events are eligible for local-model routing to the digest. Without tiers the model only explains. | Test with a stub model that labels a real risk "benign". The alert still goes out, with the model's label shown next to the code's verdict (local-models.md:12, 36, 50). |
| 7 | **Every alert shows its evidence.** | Every finding in the report names the check that fired and its evidence IDs. Every model explanation cites evidence IDs that exist (local-models.md:38). |
| 8 | **Link checks stay on the box.** `coldguardian check-link <url>` answers from a local feed cache. | Run the check with outbound network blocked. It still answers. Unit test asserts no socket opens during a lookup (landscape.md:10, 57). |
| 9 | **The model stays local, and there is no silent fallback.** | Config accepts one model URL. If it is down, the report says "model unavailable" and every finding is still reported. No other endpoint is ever called (local-models.md:53). |
| 10 | **Hostile text cannot steer it.** Banners, page titles and DNS names are data, not instructions. | The eval set includes injection cases ("ignore previous instructions", fake tool requests). Model output must stay inside the JSON schema. Any extra or unknown field is rejected (local-models.md:44, 51). |
| 11 | **Works without a model.** | Run with no model configured. Every check still runs and every alert still fires. Only the explanation text is missing. |
| 12 | **Your agents can use it.** Every command has `--json` output and clear exit codes. | `check-link --json` and `scan --json` validate against a published schema. Exit codes are 0 clean, 1 bad found, 2 unknown or incomplete. |
| 13 | **Read-only monitoring.** | The systemd unit runs with no Linux capabilities and a read-only system view, as netguard does today (netguard-audit.md:30). A test limits monitoring subprocesses to Nmap, read-only `ip` and Tailscale status commands, and the optional host watch’s exact `ss -H -tulpn` invocation. It also checks the fixed `systemctl --user` commands permitted for explicit setup and uninstall. |
| 14 | **Cleans up its own old reports.** | Configure a report retention cap (age/count) and generate 50 synthetic reports. Coldguardian prunes expired reports automatically under cap while preserving the active baseline and latest report. |
| 15 | **Proven on a real homelab for 7 days.** | Run v1 on one designated local Linux homelab box for 7 days. At low level, a clean week produces zero false pages and a planted bad-domain query produces one page with evidence. |
| 16 | **Suppresses benign MAC/DHCP churn.** | Fixture MAC-randomization and DHCP-lease rotation events on known-benign LAN devices produce zero false pages at low and medium levels, while a planted risky service still pages. |

## 5. What it will never do

- Block traffic, edit a firewall, change a router, or touch a device. It reports. You act.
- Fix things by itself. No remediation, ever. The model gets no shell and no write tools (local-models.md:38, 52).
- Guess passwords, brute force logins, or run exploit scripts. In a deep scan, Nmap's `ssh-auth-methods` checks which login methods each SSH server accepts by asking once with one made-up username and no password.
- Scan anything outside the scope you approved in setup.
- Send your scans, logs or URLs to a cloud service. The only outbound traffic is feed downloads and the alerts you turn on.
- Fall back to a cloud model.
- Run all the time. No packet capture, no IDS. Suricata and Zeek need constant capture and gateway changes; that is a different product (landscape.md:9, 32).
- Become a SIEM. Wazuh and Greenbone need 4–8 GB of RAM just to start (landscape.md:8, 29–30).
- Collect telemetry.

## 6. Quick scan vs deep scan

| | Quick scan | Deep scan |
|---|---|---|
| Question it answers | "Did anything change since I last looked?" | "What is actually on my network, and what is risky?" |
| What it looks at | Known hosts and baseline ports. New DNS hits against the bad-domain feed since the last run. Failed-login bursts on the local host. | The whole LAN range, Tailscale peers (`tailscale status --json`), WireGuard subnets, all TCP ports, service names (`nmap -sV`), SSH auth methods. |
| Risk checks | New device, new port, feed hit, auth burst. | All of quick, plus the risky-service list (Section 8). |
| Time | Target ≤60 s on a /24. | Minutes. Says so before it starts. |
| Default trigger | Manual, or the timer. | Manual, or the timer at medium and high. |

Both write one report, both list what they could not reach, and both feed the same baseline. Netguard today has one path and checks port state only, without service names (netguard-audit.md:46). Quick vs deep follows the audit's proposal (netguard-audit.md:63).

Coldguardian reads local AdGuard and Pi-hole query logs. An explicitly configured DNS API source enables read-only HTTPS queries to one inventory host.

## 7. The three levels

The level changes three things only: what pages you, how often the timer runs, and how wide the deep scan goes. It never changes what is safe to do. All levels are read-only.

| | Low: "nothing malicious" | Medium (default) | High |
|---|---|---|---|
| Pages you for | Known-bad only: a domain or link feed hit, a login burst, a new device with a risky service open. | Low, plus any new device, new port, risky service or peer change. | Medium, plus every baseline drift, coverage gap, and every finding the model marks "needs you". |
| Everything else | Daily digest. | Daily digest. | Daily digest. |
| Timer, if turned on | Quick scan daily. | Quick daily, deep weekly. | Quick every 6 hours, deep daily. |
| Deep scan ports | Top 1,000 TCP. | All TCP. | All TCP. |

The timer is off unless you turn it on in setup. Manual scans are the default (netguard-audit.md:66). Netguard has severity labels but no user policy today (netguard-audit.md:47).

## 8. Where the model is used and where plain checks are used

Rule: code finds, matches, scores and decides. The model explains and labels (local-models.md:12, 36–38; landscape.md:63–65).

| Job | Who does it |
|---|---|
| Find devices and ports | Nmap |
| Compare with the approved baseline | Code (from netguard, netguard-audit.md:25, 40) |
| Risky-service list (telnet, FTP, SMB, RDP, VNC, open Docker API, open Redis or databases, open model servers like Ollama or llama.cpp, admin panels) | Code, from a data file |
| Domain and link checks against a feed | Code, local cache |
| Tailscale and WireGuard peer lists | Code (`tailscale status --json`, `ip -j addr`) |
| Decide severity and whether to page | Code, from the level table |
| Explain a finding in plain words, for this household | Model |
| Label each finding: `risk`, `benign`, or `needs_human`, with a reason that cites evidence IDs | Model |
| Group related findings (a new device, its new ports, and its DNS hits) | Model |
| Say what evidence is missing | Model |
| Ask for more facts through a short allowlist of read-only lookups (baseline history, port detail, feed lookup) | Model asks, code checks the request and answers |
| Phrase a safe next step for you to take | Model |

The model never scans, never matches CVEs or feeds, never parses ACLs, and never runs anything (landscape.md:65).

For v1, Task 7 will pick one free public phishing and malware URL feed that needs no key and whose terms allow local caching. Task 7 will name the feed in the README and use fixtures in tests.

**Where the model runs.** v1: llama.cpp on an RTX 3090. The first candidates are Qwen3.5-27B Q4_K_M (~18 GB) and Qwen3.5-9B Q6_K (~7.5 GB). The eval picks the smallest one that passes (local-models.md:5–6). Later: Qwen3.5-2B or 4B Q4_K_M on CPU. On one published CPU benchmark, a 1K-in/200-out explanation took about 18 s (2B) and 42 s (4B). That speed is fine for a daily digest but too slow for live chat (local-models.md:10–11, 30). The CPU model ships only after it passes the same eval. 3090 speed and quantized accuracy are not measured yet (local-models.md:14).

## 9. How it fits the Cold Stack

Coldguardian is standalone first. It is fully useful with no other Cold product installed. When another product is there, it can use it. When that product goes away, Coldguardian keeps working.

| Cold product | Optional link | Owner of the outcome |
|---|---|---|
| Coldbox | Runs Coldguardian's tests, its eval set, and the lab network for deep-scan tests in throwaway VMs. Development time only. | Coldbox owns the VMs. |
| Coldverify | After you fix a finding, Coldverify re-runs that one check and writes an evidence package proving it is closed. Eval runs use the same evidence format. | Coldguardian owns the finding. Coldverify owns the proof. |
| Coldfix | False alarms and misses that you mark become candidate rule changes or new eval cases. Coldfix decides which ones are real lessons. | Coldfix owns lesson validity. |
| Coldlocker | Offers `check-link` and `status` as read-only tools to your agents, so Claude or Codex can check a link before opening it. | Coldlocker owns cross-agent access. Coldguardian still enforces read-only. |
| Coldvault | Writes reports and digests into your Obsidian vault. | Coldvault owns storage. |
| Coldrelease | Prepares the public source export. | Coldrelease owns publication safety. |

Coldguardian cleans up its own old reports. It does not rely on Coldcleaner for that.

## 10. What success looks like

- A new user goes from nothing to a first report in one command and five answers.
- At low level, a week passes with zero pages on a clean network and one page when a planted bad domain is queried.
- Every page includes its evidence, and a person can act on it without opening another tool.
- No user ever has to ask "is this thing still running and eating RAM?"
- The model passes the 30-case eval before it ships, and again after every model or runtime change (local-models.md:13, 53).

## 11. Phases

1. **v1: prove it on one homelab.** Quick and deep scans, three levels, link and DNS feed check, 3090 model explanations, one-command install. See `v1-plan.md`.
2. **Smaller model.** CPU 2B/4B model, same eval, same pass bar.
3. **Wider checks.** UPnP and router port forwards, Tailscale policy review, WireGuard AllowedIPs, optional Lynis host audit, known-vulnerable version matching (landscape.md:55–59).
4. **Stack links and open source.** The Section 9 links, then a public release through Coldrelease.

## 12. Name

Checked 2026-11-20 with `gh search repos <name> --match name --limit 100`, `https://pypi.org/pypi/<name>/json`, and `https://registry.npmjs.org/<name>`. No trademark search was done.

| Name | GitHub repos with the name | PyPI | npm | Notes |
|---|---|---|---|---|
| **Coldguardian** | 2 (Ashborn-1111/ColdGuardian, empty, 0★; pbalamurali74-hue/coldguardian-ai-ibm-z-datathon, a hackathon repo) | free | free | The owner's first idea. Says what it does. |
| Coldguard | 82, mostly cold-chain and vaccine temperature monitors (e.g. Santhosh-zeta/ColdGuard) | free | free | Shortest, but buried in search and means "keeps things cold" to many people. |
| Colddefend | 0 | free | free | Original working name. Clean namespace. A verb, like Coldfix. |
| Coldprotect | 0 | free | free | Clean, but bland. Reads like a setting, not a product. |
| Coldblueteam | 0 | free | free | Clean, but long. "Blue team" is security jargon the low-level user won't know. |

The owner chose **Coldguardian** on 2026-11-20.

## 13. Recorded decisions & approved add-ons (2026-11-21)

- **Name:** Coldguardian (approved 2026-11-20).
- **v1 URL/domain feed:** Free, no-key public feed whose terms allow local caching (approved 2026-11-20, D3).
- **v1 live homelab host:** Designated locally by the owner on one Linux homelab machine (configured outside the repo; never hardcoded in tracked files).
- **Public-vs-private parity:** Once released publicly through Coldrelease, the public repo stays synced within ≤3 days of user-facing private `main` changes.
- **Approved add-ons (Wave C):**
  - `coldguardian explain <finding-id>` — on-demand local-model drilldown for a single finding without waking the model on quiet runs.
  - `coldguardian approve <finding-id> --reason "..."` — audited CLI baseline approval recording reason and timestamp.
