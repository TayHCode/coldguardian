# Netguard audit

## 10-line summary

1. Netguard is a local, alert-only scanner with no remediation or firewall edits. `README.md:3–11`
2. Nmap discovers IPv4 devices, scans configured TCP ports, and compares them with an approved baseline. `netguard.py:174–205`
3. DNS and login checks use heuristics; there is no domain reputation feed. `netguard.py:209–254` `README.md:135–142`
4. Setup is manual; systemd starts the timer five minutes after boot and repeats about every 30 minutes. `README.md:73–90` `systemd/netguard.timer:1–11`
5. Optional ntfy sends pages for new devices, ports, and baseline problems, plus a daily digest. `README.md:92–126`
6. Ollama returns only advisory severity and review text. It has no tools or actions. `netguard.py:343–375`
7. Keep the scanner, baseline approval, coverage tracking, private reports, and notification retry state. `netguard.py:582–693`
8. Rework scan profiles, user security levels, peer discovery, link checks, setup, and model use for the requested product. `netguard.py:696–716`
9. The public upstream source reads its network and host inventory from an editable configuration file. `config.example.json:1–18`
10. The bundled Ollama service starts the model server on loopback with cloud access disabled. `systemd/ollama.service:9–11`

## What it checks and how it runs

Download the [homelab-netguard source archive at commit `051d76e`](https://api.github.com/repositories/1431360051/zipball/051d76e68c84a947754d46eb4be0652c6b2167b4). The file and line citations below refer to this revision.

| Check | Current behavior |
|---|---|
| Scope | Config names a private IPv4 LAN CIDR and exact IPv4 addresses for named hosts. Public config supports local, DNS, and optional hosts. `README.md:31–49` |
| Discovery | Nmap probes the configured LAN and listed hosts. Unreachable listed hosts are coverage findings. `netguard.py:174–195` |
| Ports | Nmap TCP-connect scans configured ports. Code defaults to all TCP ports, but the sample config selects a shorter list. It does not identify service versions or run vulnerability scripts. `netguard.py:135–165` `config.example.json:12–17` |
| Baseline | A person approves the initial complete snapshot. New hosts/ports remain findings until approval; a config change invalidates the baseline. `README.md:61–71` `netguard.py:657–690` |
| DNS and auth | Reads configured AdGuard logs and flags user-listed suffixes, long/random-looking labels, and failed Linux logins on the local host. It stores counts and client IPs, not raw lines or domain names. `netguard.py:209–254` `netguard.py:281–340` |
| Coverage | Log reads cap at 1 MiB per chunk, 32 chunks per source, and 60 seconds total. Rotation, backlog, parse errors, and incomplete scans are reported. `netguard.py:26–30` `netguard.py:257–340` |
| Model | With findings, Ollama receives sanitized findings and must return a fixed severity/proposal JSON. It is advisory and has a 120-second timeout; findings remain if triage fails. `netguard.py:343–375` `netguard.py:681–689` |

The service runs as netguard without Linux capabilities, with a read-only system view and write access to its state directory. It runs after network-online and Ollama; a separate OnFailure unit sends a generic alert. The timer adds up to two minutes of random delay. `systemd/netguard.service:1–28` `systemd/netguard.timer:1–11` `systemd/netguard-notify-failure.service:1–18`

Quick start copies and edits a config, runs a scan, reviews it, and approves the baseline. Service setup also creates a user, copies files, installs units, and sets up SSH to DNS hosts. Reports and state use private file modes; reports go to latest.md, stdout, and the journal. `README.md:13–29` `README.md:73–90` `netguard.py:499–536`

ntfy pages each new device/port/baseline item, then can repeat after 14 days. Other findings go into a digest after 08:00 host local time. The topic is read from a secret file; messages contain bounded text sent to ntfy.sh. `netguard.py:539–620` `notifications.py:28–85` `README.md:92–126`

## Reuse, rework, and drop

| Decision | Parts |
|---|---|
| Reuse | Bounded Nmap execution and validation, manual baseline approval, host/port diffing, coverage findings, private reports, and notification retry state. `netguard.py:135–205` `netguard.py:582–693` |
| Rework | Make setup and peer sources simple; add quick/deep profiles, actual user policy, service risk checks, link checks, and a read-only model agent. Keep local reporting and clear coverage. `README.md:31–49` |
| Drop | Make the upstream 30-minute scan schedule optional. Omit the bundled Ollama service when using an existing model endpoint. `systemd/netguard.timer:4–8` `systemd/ollama.service:9–11` |

## Gaps against the requested product

- **Quick/deep:** One scan path runs on a repeating timer. There is no quick/deep switch, and current scans check TCP port state without identifying services. `netguard.py:696–716` `netguard.py:174–195`
- **Security levels:** The model emits info/low/medium/high/critical, but users cannot choose a protection level or change scan/alert behavior. `netguard.py:30–31` `README.md:31–44`
- **Tailscale/WireGuard:** The public scanner reads configured peer IPs. Automatic peer discovery would require a separate lookup. `netguard.py:70–90`
- **Phishing and links:** No URL input or reputation check. DNS checks use user-listed suffixes and label heuristics. `netguard.py:209–254` `README.md:135–142`
- **One-command setup:** Current instructions require manual config, dependencies, users, files, units, SSH access, and baseline approval. `README.md:13–29` `README.md:73–90`
- **Model agent and placement:** Current code is optional Ollama classification, defaulting to loopback, with a loopback Ollama unit. The requested llama.cpp endpoint and live deployment are UNVERIFIED. `netguard.py:343–375` `systemd/ollama.service:1–25`

## Homelab-specific hard-coding

Treat the LAN range, peer addresses, monitored hosts, DNS log sources, and scanner identity as site-specific settings.

Public/oss-prep replaces host identities with editable config, but keeps Linux and AdGuard defaults: the AdGuard query-log path, /var/log/auth.log, /opt/netguard, /var/lib/netguard, and /etc/netguard/ntfy-topic. The sample uses 192.168.1.x addresses. Notification delivery is fixed to ntfy.sh, not a configurable local or self-hosted server. Users with other DNS/log sources, operating systems, or alert servers need edits or adapters. `config.example.json:1–18` `netguard.py:70–128` `systemd/netguard.service:8–26` `notifications.py:28–61`

## Smallest path to V1

1. Start from the public upstream snapshot. Keep its private local reports and manual baseline approval. `README.md:61–71`
2. Add one setup command for LAN and optional Tailscale/WireGuard peers, model, and alerts. Write config and offer an optional quiet timer. `README.md:13–29` `README.md:73–90`
3. Add quick and deep profiles: known hosts/selected ports for quick, selected LAN and peers/all TCP ports/service identification for deep. Keep coverage warnings. `netguard.py:174–195`
4. Make low/medium/high real user policies. Add a URL-check command with a local list or privacy-reviewed reputation source, and label heuristic matches as uncertain. `netguard.py:209–254`
5. Give the local model read-only scanner/report tools so it can select checks and explain findings. Use a LAN-hosted llama.cpp service first; keep model traffic on the LAN and remediation disabled. Plan the smaller CPU model later.
6. Keep ntfy optional and manual scans as the default. Validate with fixtures and a small user-owned lab before enabling a schedule. `README.md:92–126` `systemd/netguard.timer:1–11`

The audit did not verify which model endpoint the live installation uses.

