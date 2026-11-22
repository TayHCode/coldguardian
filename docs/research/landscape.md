# Home network monitoring: existing tools and what to reuse

## Summary

1. Search-first was inconclusive: 0 plausible, 13 adjacent among 123 metadata candidates; the search was bounded and no project was run.
2. Reuse homelab-netguard’s Nmap scan, approved baseline, read-only DNS/auth checks, alert-only reports, and optional local triage. [Upstream README in the pinned ZIP](https://api.github.com/repositories/1431360051/zipball/051d76e68c84a947754d46eb4be0652c6b2167b4)
3. Use Nmap and optional Lynis host audits; do not build another scanner. [Nmap](https://nmap.org/book/man-legal) · [Lynis](https://github.com/CISOfy/lynis)
4. Greenbone and full Wazuh are too heavy for default setup: 4 GB and 8 GiB documented RAM minimums. [Greenbone](https://greenbone.github.io/docs/latest/22.4/container/) · [Wazuh](https://documentation.wazuh.com/current/quickstart.html)
5. CrowdSec is light for service logs; Suricata and Zeek need continuous packet capture and extra network setup. [CrowdSec](https://docs.crowdsec.net/u/getting_started/intro/) · [Suricata](https://docs.suricata.io/en/latest/what-is-suricata.html) · [Zeek](https://zeek.org/about/)
6. Reuse an existing Pi-hole or AdGuard DNS service and cached URL feeds; offline lookups age between feed updates. [Pi-hole](https://docs.pi-hole.net/main/prerequisites/) · [PhishTank](https://phishtank.net/developer_info.php) · [Safe Browsing](https://developers.google.com/safe-browsing/v4/local-databases)
7. Read Tailscale policy tests and WireGuard config instead of adding a scanner. [Tailscale](https://tailscale.com/docs/features/access-control/grants/grants-explained) · [WireGuard](https://www.wireguard.com/quickstart/)
8. Cloudflare, NVIDIA, and Snyk tools inspect agent code, skills, or MCP configuration, not home networks. [Cloudflare](https://github.com/cloudflare/security-audit-skill) · [SkillSpector](https://github.com/NVIDIA/SkillSpector) · [Agent Scan](https://github.com/snyk/agent-scan)
9. AiSOC and Vigil are open-source AI SOC stacks, but heavier than an alert-only homelab scanner. [AiSOC](https://github.com/beenuar/AiSOC) · [Vigil](https://github.com/Vigil-SOC/vigil)
10. Prioritize public vulnerable services, stolen credentials, and phishing; use a local model to explain facts, not to decide or perform actions. [Verizon 2026 DBIR](https://www.verizon.com/about/news/breach-industry-wide-dbir-finds) · [Upstream README in the pinned ZIP](https://api.github.com/repositories/1431360051/zipball/051d76e68c84a947754d46eb4be0652c6b2167b4)

Resource figures below are published minimums where available, not measured runtime. UNVERIFIED means I found no comparable vendor figure.

## Search-first result

I used search-first on 2026-11-20. Five queries covered homelab monitoring, network audits, agent security, AI SOC, and intrusion detection. The tool evaluated 123 unique candidates, with 0 plausible and 13 adjacent; results were bounded to 30 per query, so the verdict was inconclusive. AiSOC was the closest broad match. A focused search returned 13 candidates, 0 plausible and 1 adjacent, InSpectre. It also surfaced Masscanned, which is a honeypot rather than a scanner. A compare call hit GitHub's 403 limit for Masscanned activity/release data. Inspection was metadata/README only; nothing was cloned, installed, or run.

## Existing pieces

| Tool | What it does, weight, and setup | License and fit |
|---|---|---|
| **homelab-netguard, already here** | Nmap discovery and TCP checks, explicit scope, approved baseline, read-only DNS/auth logs, reports, ntfy, optional Ollama, systemd timer. Light starting point; no RAM benchmark in the README. | MIT per repository metadata. Reuse its scan/diff/report path. [Upstream README in the pinned ZIP](https://api.github.com/repositories/1431360051/zipball/051d76e68c84a947754d46eb4be0652c6b2167b4) |
| **Nmap / Masscan** | Nmap is one-shot with no monitoring daemon; RAM varies by scan size (UNVERIFIED). Masscan sends asynchronous high-rate probes and is unnecessary for a small LAN; RAM UNVERIFIED. | Nmap NPSL restricts redistribution inside proprietary products; Masscan AGPL-3.0. Use bounded Nmap scans. [Nmap](https://nmap.org/book/man-legal) · [Masscan](https://github.com/robertdavidgraham/masscan) |
| **Lynis** | On-demand Unix/Linux host audit, no always-on daemon; RAM UNVERIFIED. Low setup. | GPL-3.0. Good optional audit for Linux hosts. [Project](https://github.com/CISOfy/lynis) |
| **Greenbone / OpenVAS** | Docker Compose stack and feed sync; 4 GB RAM/20 GB disk minimum, 8 GB/60 GB recommended. Heavy. | Mostly GPL components; feed terms are separate. Use only for opt-in deep scans. [Requirements](https://greenbone.github.io/docs/latest/22.4/container/) · [licenses](https://www.greenbone.net/en/license-information/) |
| **Wazuh** | Per-host agents plus server, indexer, and dashboard. For 1 to 25 agents, quickstart recommends 4 vCPU, 8 GiB RAM, and 50 GB storage. Heavy. | GPL-2.0 and Apache-2.0 components; engine also has AGPL-3.0 code. Useful if already installed, too much for the default. [Quickstart](https://documentation.wazuh.com/current/quickstart.html) · [license](https://github.com/wazuh/wazuh) |
| **CrowdSec** | Log engine daemon with optional firewall/proxy bouncer; 1 CPU, 100 MB RAM, 1 GB disk minimum. Lightweight; integration depends on the logs and enforcement choice. | MIT. Fits exposed-service logs, not LAN inventory. [Docs](https://docs.crowdsec.net/u/getting_started/intro/) · [FAQ](https://docs.crowdsec.net/u/troubleshooting/general/) |
| **Suricata / Zeek** | Continuous IDS/traffic logs. Need persistent capture, rules, and a suitable gateway or TAP/mirror. RAM varies by throughput and rules (UNVERIFIED). | Suricata GPL-2.0; Zeek BSD. Too much for a timer-based scan. [Suricata](https://docs.suricata.io/en/latest/what-is-suricata.html) · [Zeek](https://zeek.org/about/) |
| **Pi-hole / AdGuard Home** | DNS blocklists and query logs. Pi-hole minimum: 512 MB RAM and 2 GB disk, with FTL daemon. AdGuard is a standalone service; RAM minimum UNVERIFIED. | Pi-hole core EUPL-1.2, FTL GPL-2.0; AdGuard GPL-3.0. Reuse the DNS server already in use. [Pi-hole requirements](https://docs.pi-hole.net/main/prerequisites/) · [core](https://github.com/pi-hole/pi-hole/blob/master/LICENSE) · [FTL](https://github.com/pi-hole/FTL/blob/master/LICENSE) · [AdGuard](https://github.com/AdguardTeam/AdGuardHome/blob/master/LICENSE.txt) |
| **Tailscale / WireGuard** | Read existing Tailscale policy/tests and WireGuard peer config with its current tools; no extra scanner. Added RAM UNVERIFIED. Tailscale grants add up, so a broad grant can open access. | Tailscale client BSD-3-Clause; WireGuard tools GPL-2.0-only. Reuse existing policy/config. [Tailscale policy](https://tailscale.com/docs/features/access-control/grants/grants-explained) · [client license](https://github.com/tailscale/tailscale/blob/main/LICENSE) · [wg tools](https://github.com/WireGuard/wireguard-tools) |
| **URL feeds** | URLhaus and PhishTank data can be cached for local lookups; Google Safe Browsing also documents a local database. No daemon; RAM/index size UNVERIFIED. Feed freshness needs updates. | Data terms are not code licenses. URLhaus API requires an auth key; PhishTank feeds update hourly and automated downloads need an application key. Confirm redistribution terms before bundling. [URLhaus](https://urlhaus.abuse.ch/api/) · [PhishTank](https://phishtank.net/developer_info.php) · [Safe Browsing local DB](https://developers.google.com/safe-browsing/v4/local-databases) |

### Direct near-matches

**Secwatch** claims a one-command systemd install for reverse-proxy/app logs, SSH/auth, CVEs, and optional local-LLM analysis. Its repo reports MIT. It does not advertise LAN inventory/port scanning; RAM is UNVERIFIED, and its lightweight claim is not an independent measurement. [Repository](https://github.com/Paco5687/secwatch)

**InSpectre** combines LAN discovery, Nmap ports, Trivy image checks, container/Proxmox management, and a web UI. It requires Docker; RAM is UNVERIFIED. GitHub reports AGPL-3.0 while its README badge says MIT, so resolve the license before reuse. [Repository and README](https://github.com/thefunkygibbon/InSpectre)

## Agent security packs and AI SOCs

Cloudflare's security-audit-skill is an MIT coding-agent workflow for auditing source code. It uses coverage tracking and independent finding checks and expects a tool-using agent with subagents. Cloudflare's Apache-2.0 skills collection mainly covers Cloudflare products. UnitOneAI/SecuritySkills is an MIT guidance pack, not a running scanner. Reuse relevant checklists, not agent orchestration. [Cloudflare audit](https://github.com/cloudflare/security-audit-skill) · [Cloudflare skills](https://github.com/cloudflare/skills) · [UnitOneAI](https://github.com/UnitOneAI/SecuritySkills)

NVIDIA SkillSpector and Snyk Agent Scan are Apache-2.0 CLI checks for skills/MCP components, not LAN monitors; RAM minimums UNVERIFIED. Snyk Agent Scan requires a Snyk token, so it is not a fully local threat source. [SkillSpector](https://github.com/NVIDIA/SkillSpector) · [Agent Scan](https://github.com/snyk/agent-scan)

AiSOC is MIT and documents Docker Compose, Python/Bash, 8 GB RAM, 20 GB disk, and a roughly 2 GB model download. Vigil is Apache-2.0 and supports Docker/local Ollama; RAM UNVERIFIED. Both add SOC workflows and pipelines, not a simple scan wrapper. Borrow an event ledger or human-approval pattern only if needed. [AiSOC](https://github.com/beenuar/AiSOC) · [Vigil](https://github.com/Vigil-SOC/vigil)

## Checks to prioritize

No representative homelab incident-frequency dataset was found. The first three ranks use global Verizon breach data as a proxy. The rest are high-value home-network checks, not an observed frequency order.

1. **Public vulnerable services and stale firmware.** The 2026 DBIR says software flaws started 31% of breaches and overtook stolen credentials. Check WAN forwards, public admin panels, router/NAS/hypervisor services, and update status. A LAN Nmap scan cannot prove WAN exposure. [Verizon](https://www.verizon.com/about/news/breach-industry-wide-dbir-finds) · [CISA router guidance](https://www.cisa.gov/sites/default/files/publications/HomeRouterSecurity2011.pdf)
2. **Default/reused credentials and weak SSH.** Stolen credentials ranked second in the 2026 DBIR. Check defaults, exposed admin logins, SSH root/password access, and failed-login spikes. [Verizon](https://www.verizon.com/about/news/breach-industry-wide-dbir-finds) · [CISA](https://www.cisa.gov/sites/default/files/publications/HomeRouterSecurity2011.pdf) · [OpenSSH settings](https://docs.oracle.com/en/operating-systems/oracle-linux/openssh/openssh-ModifyingOpenSSHServerConfigurationFiles.html)
3. **Phishing and malicious links.** The 2026 DBIR reports text/voice social-engineering success 40% higher than email phishing; this is a success-rate comparison, not a homelab incident share. Use updated local URL lists; avoid sending private URLs to cloud lookups. [Verizon](https://www.verizon.com/about/news/breach-industry-wide-dbir-finds) · [NSA](https://media.defense.gov/2023/Feb/22/2003165170/-1/-1/0/CSI_BEST_PRACTICES_FOR_SECURING_YOUR_HOME_NETWORK.PDF)
4. **UPnP, WAN administration, and forgotten forwards.** CISA and NSA advise disabling unneeded UPnP and router administration from the WAN. [CISA](https://www.cisa.gov/sites/default/files/publications/HomeRouterSecurity2011.pdf) · [NSA](https://media.defense.gov/2023/Feb/22/2003165170/-1/-1/0/CSI_BEST_PRACTICES_FOR_SECURING_YOUR_HOME_NETWORK.PDF)
5. **Tailnet/VPN access and device/port changes.** Review Tailscale grants, tags, subnet routes, WireGuard peers/AllowedIPs, and compare devices/ports with the approved netguard baseline. Tailscale policy tests catch unintended access changes. [Tailscale](https://tailscale.com/docs/features/access-control/grants/grants-explained) · [WireGuard](https://www.wireguard.com/quickstart/) · [Upstream README in the pinned ZIP](https://api.github.com/repositories/1431360051/zipball/051d76e68c84a947754d46eb4be0652c6b2167b4)

## Where the local model helps

**Inference from the current design:** use a local model to summarize structured findings, explain why a service is new for this household, group related DNS/auth/port observations, and phrase a safe next step. The existing netguard constrains model output and never executes it. [Upstream README in the pinned ZIP](https://api.github.com/repositories/1431360051/zipball/051d76e68c84a947754d46eb4be0652c6b2167b4)

Do not use a model to scan ports, match versions to CVE/KEV data, check URLs against feeds, parse ACLs, or run remediation. Those are exact rule checks. Local inference can keep inputs local, but it does not make an ambiguous event accurate. Before requiring the proposed 2B CPU model, measure latency and triage accuracy on fixed cases. This research did not benchmark it.

