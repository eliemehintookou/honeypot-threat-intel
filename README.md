# Honeypot Threat Intelligence Analyzer

A threat intelligence pipeline built around a [Cowrie](https://github.com/cowrie/cowrie) SSH/Telnet honeypot exposed on a public VPS. The project collects real attack traffic from the internet, enriches it with IP reputation data, and maps observed attacker behavior to the MITRE ATT&CK framework.

## Architecture

- A public VPS (OVHcloud, Ubuntu 24.04) exposes ports 22 (SSH) and 23 (Telnet) via iptables NAT redirection to a Cowrie honeypot listening on 2222/2223.
- Cowrie simulates a realistic Linux server (`prod-app02`) and logs every connection attempt, credential pair, and command typed by attackers in structured JSON.
- Admin SSH access is isolated on a non-standard port, with a dedicated non-root system user running the honeypot as a systemd service for resilience.

## Pipeline

1. **`src/parser.py`** — parses Cowrie's JSON log and builds a per-IP profile (connections, login attempts, commands).
2. **`src/enrich.py`** — queries the [AbuseIPDB](https://www.abuseipdb.com/) API for each unique attacker IP (reputation score, country, ISP, Tor usage).
3. **`src/mitre.py`** — classifies commands typed by attackers against a set of MITRE ATT&CK technique rules (discovery, tool transfer, permission modification, scheduled tasks, etc.).
4. **`src/analyze.py`** — quick command-line summary (top countries, highest-risk IPs).
5. **`src/report.py`** — generates a styled HTML report combining all of the above.

## Results (first 48 hours)

- 227 unique attacker IPs observed
- 67% scored 90+/100 on AbuseIPDB
- Real malware download attempts captured (Mirai/Miori-like IoT botnet behavior via `wget` and `busybox`)
- Full technique breakdown mapped to MITRE ATT&CK (T1082, T1105, T1222.002, T1053.003, T1552.001, T1059.004)

See `reports/threat_report.html` for a sample report.

## Stack

Python 3, `requests`, Cowrie, iptables, systemd, AbuseIPDB API.
