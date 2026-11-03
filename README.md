# Heimdall Lite

A free, laptop-only network watchtower that compares rule-based (Suricata) and ML-based detection on real malware traffic, and alerts via Discord.

> Status: work in progress (Phase 0 – environment setup)

## Goal
Reproducible, offline, $0 pcap + live-lab analysis pipeline that honestly measures where rules vs ML win and fail.

## Detection targets
Botnet C2 beaconing, DGA domains, port scanning, SSH brute force, (optional) DNS tunneling.

## Planned pipeline
Traffic (pcap / lab VM) -> capture windows -> Zeek/tshark features + Suricata rules + ML -> suspicious? -> Discord alert + saved pcap/log -> Streamlit dashboard

## Stack
Ubuntu Server 24.04 (VirtualBox), Suricata, Zeek, tshark, Python (pandas, scikit-learn), Streamlit.

## Repo structure
| Folder | Purpose |
|---|---|
| `rules/` | Custom Suricata rules |
| `scripts/` | Setup and helper scripts |
| `reports/` | Incident reports and evaluation |
| `pcaps/` | Local pcaps (gitignored, not published) |

## Progress
- [x] Sensor VM (Ubuntu Server 24.04)
- [x] Install Suricata, replay first pcap
- [ ] Zeek features + custom rules
- [ ] ML detector + evaluation
- [ ] 24/7 service + Discord alerts
- [ ] Dashboard + writeups

## Scope and limits
Lab / own-network use only. Detection is alert-only (no blocking). CTU-13 is an older dataset and weak on modern encrypted traffic; live mode will produce false positives.
