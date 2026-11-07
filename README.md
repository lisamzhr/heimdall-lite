# Heimdall Lite

A free, laptop-only network detection lab that **compares rule-based (Suricata) and ML-based detection** on malware traffic, and reports honestly where each one wins and fails.

> Status: work in progress. Rules side working (incident reports, replay script); ML evaluation, alerting and dashboard in progress.

## Goal
Reproducible, offline, $0 pcap analysis pipeline: replay traffic, detect with Suricata rules and an ML model, compare the results, alert on Discord, and show everything in a small dashboard.

## Pipeline
```mermaid
flowchart LR
  A[pcap / lab capture] --> B[Suricata rules]
  A --> C[Flow features]
  C --> D[ML model]
  B --> E{suspicious?}
  D --> E
  E -->|yes| F[Discord alert + saved pcap/log]
  E --> G[Streamlit dashboard]
  F --> G
```

## Detection targets and how each is covered
| Target | Data | Detection |
|---|---|---|
| Botnet C2 beaconing | CTU-13 + malware-traffic-analysis.net pcaps | Suricata rules vs Random Forest on flow features |
| Port scanning | Own lab traffic (Kali VM -> sensor VM) | Suricata rules |
| SSH brute force | Own lab traffic (Kali VM -> sensor VM) | Suricata rules |
| DGA domains | Domain lists | Stretch goal |

## Stack
Ubuntu Server 24.04 (VirtualBox), Suricata 8, Wireshark (manual cross-check), Python (pandas, scikit-learn), Streamlit, Discord webhook, jq.

## Repo structure
| Folder | Purpose |
|---|---|
| `rules/` | Custom Suricata rules |
| `scripts/` | Helper scripts (e.g. `replay_pcap.sh`) |
| `reports/` | Incident reports and evaluation |
| `pcaps/` | Local pcaps (gitignored, not published) |

## Reproduce an analysis
```bash
scripts/replay_pcap.sh pcaps/<file>.pcap
```
Runs Suricata offline on the pcap and prints the alert count and the top rules. Output goes to `out/` (gitignored).

## Progress
- [x] Sensor VM (Ubuntu Server 24.04) and Suricata with ET Open rules
- [x] Replay script
- [x] Incident report 01: Cobalt Strike beaconing, cross-checked in Wireshark
- [x] Incident reports 02-03 (port scan, SSH brute force)
- [x] Custom Suricata rules
- [x] ML detector + rules-vs-ML evaluation
- [x] Discord alerts (replay mode) + dashboard
- [ ] Demo video

## Scope and limits
- Lab / own-network use only. Detection is alert-only (no blocking).
- "Live" behaviour is simulated by replaying pcaps; there is no 24/7 sensor.
- CTU-13 is old (2011-era botnets) and weak on modern encrypted traffic. Its full-traffic pcaps are not public (privacy); the botnet-only pcaps are, plus labelled flows. Results are reported with this in mind.
- ML on labelled lab/CTU-13 data will produce false positives on real networks.

## Alerting (replay mode)
`scripts/run_pipeline.sh <pcap>` replays a capture through Suricata and posts one summary to Discord when it finds severity 1-2 rule hits or a host contacting 26+ destinations in a minute. Evidence pcaps are saved locally and attached when small.

![Discord alert](reports/img/discord-alert.png)

**Live demo tip:** wait at least 1-2 minutes after Suricata prints "Engine started" before generating traffic — rule loading takes time, and anything sent before that is missed.

## Demo flow (live mode)
Three terminals, run in this order:

1. **Suricata (live capture)** — VM, terminal 1:
   ```bash
   cd ~/heimdall-lite
   mkdir -p out/live
   sudo rm -f out/live/eve.json out/live/fast.log
   sudo suricata -c /etc/suricata/suricata.yaml -s rules/heimdall.rules -i enp0s8 -l out/live -k none
   ```
   Wait for `Engine started`, then wait **1-2 more minutes** before generating traffic — rule loading takes time, and anything sent too early is missed.

2. **Discord watcher** — VM, terminal 2 (new SSH session):
   ```bash
   cd ~/heimdall-lite
   sudo chmod 644 out/live/eve.json
   source ~/venv-heimdall/bin/activate
   python scripts/live_watch.py out/live/eve.json
   ```
   Prints `Watching out/live/eve.json ...` and then one line per alert it forwards.

3. **Generate traffic** — Windows PowerShell:
   ```powershell
   nmap -sS -T4 -p 1-1024 192.168.56.111
   ```
   Within a few seconds, terminal 2 prints `RULE ALERT ...` and a message appears in Discord.

Stop with Ctrl+C in terminal 2, then terminal 1.

**Note:** live mode detects and alerts from Suricata's `eve.json` stream; it does not attach evidence pcaps (no file exists yet to cut a slice from). Evidence pcaps are a replay-mode feature only (`scripts/run_pipeline.sh`, see below).

## Replay mode (with evidence pcap)
For a capture already on disk:
```bash
scripts/run_pipeline.sh pcaps/<file>.pcap
```
Replays it through Suricata, posts one Discord summary if anything looks suspicious, and saves a small evidence pcap (only the flagged hosts' traffic) under `evidence/` — attached to the message when under 5 MB.
