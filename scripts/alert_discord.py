#!/usr/bin/env python3
"""Summarise a Suricata replay and post ONE Discord message if it looks suspicious.

Usage (from the repo root):
  python scripts/alert_discord.py out/<replay-dir> pcaps/<file>.pcap [--dry-run] [--force]
"""
import json
import os
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

import requests

FANOUT_MIN = 26                  # distinct destinations per source per minute (see ml/sanity.py)
ATTACH_MAX = 5 * 1024 * 1024     # attach evidence pcap only if it is small


def load_env(path=".env"):
    p = Path(path)
    if not p.exists():
        return
    for line in p.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def cut(text, n=1000):
    return text if len(text) <= n else text[: n - 3] + "..."


def read_eve(path):
    alerts, dests = [], defaultdict(set)
    with open(path) as fh:
        for line in fh:
            try:
                e = json.loads(line)
            except ValueError:
                continue
            kind = e.get("event_type")
            if kind == "alert":
                if "invalid checksum" not in e["alert"]["signature"]:
                    alerts.append(e)
            elif kind == "flow":
                start = e.get("flow", {}).get("start", "")
                if start:
                    dests[(e["src_ip"], start[:16])].add(e["dest_ip"])
    return alerts, dests


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        sys.exit(__doc__)
    force, dry = "--force" in sys.argv, "--dry-run" in sys.argv
    outdir = Path(args[0])
    pcap = Path(args[1]) if len(args) > 1 else None
    name = pcap.name if pcap else outdir.name

    alerts, dests = read_eve(outdir / "eve.json")
    named = [a for a in alerts
             if not a["alert"]["signature"].startswith("SURICATA") and a["alert"]["severity"] <= 2]

    fan = {}
    for (src, minute), s in dests.items():
        fan[src] = max(fan.get(src, (0, "")), (len(s), minute))
    flagged = {s: v for s, v in fan.items() if v[0] >= FANOUT_MIN}

    print(f"alerts={len(alerts)}  rule_hits(non-anomaly, severity<=2)={len(named)}  "
          f"fanout_flagged_hosts={len(flagged)}")
    if not (named or flagged or force):
        print("Nothing suspicious by our criteria; no Discord message sent.")
        return

    sigs = Counter(a["alert"]["signature"] for a in named).most_common(5)
    rules_txt = "\n".join(f"{n}x {s}" for s, n in sigs) or "none"
    pairs = Counter((a["src_ip"], a["dest_ip"]) for a in named).most_common(3)
    pairs_txt = "\n".join(f"{n}x {s} -> {d}" for (s, d), n in pairs) or "none"
    top_fan = sorted(flagged.items(), key=lambda x: -x[1][0])[:3]
    fan_txt = "\n".join(f"{s}: {c} destinations in minute {m}" for s, (c, m) in top_fan) or "none"

    ips = list(dict.fromkeys([ip for (s, d), _ in pairs for ip in (s, d)] + list(flagged)))[:4]
    evidence, attach = None, False
    if pcap and pcap.exists() and ips:
        Path("evidence").mkdir(exist_ok=True)
        evidence = Path("evidence") / f"{pcap.stem}-suspicious.pcap"
        bpf = " or ".join(f"host {ip}" for ip in ips)
        try:
            subprocess.run(["tcpdump", "-nr", str(pcap), "-w", str(evidence), bpf],
                           check=True, capture_output=True)
            attach = evidence.stat().st_size <= ATTACH_MAX
        except (OSError, subprocess.CalledProcessError):
            evidence = None
    ev_txt = "not saved"
    if evidence:
        kb = evidence.stat().st_size // 1024
        ev_txt = f"{evidence} ({kb} KB), " + ("attached" if attach else "too large to attach, kept locally")

    sev1 = any(a["alert"]["severity"] == 1 for a in named)
    embed = {
        "title": cut(f"Heimdall Lite: suspicious activity in {name}", 250),
        "description": f"{len(alerts)} alerts total, {len(named)} non-anomaly rule hits (severity 1-2).",
        "color": 0xE74C3C if sev1 else 0xE67E22,
        "fields": [
            {"name": "Rules (Suricata)", "value": cut(rules_txt)},
            {"name": "Top source -> destination", "value": cut(pairs_txt)},
            {"name": f"Behaviour: fan-out >= {FANOUT_MIN} destinations/min", "value": cut(fan_txt)},
            {"name": "Evidence", "value": cut(ev_txt)},
        ],
        "footer": {"text": "Replay mode: simulated live detection, alert only"},
    }
    payload = {"username": "Heimdall Lite", "embeds": [embed]}
    if dry:
        print(json.dumps(payload, indent=2))
        return

    load_env()
    url = os.environ.get("DISCORD_WEBHOOK_URL")
    if not url:
        sys.exit("DISCORD_WEBHOOK_URL is not set (.env)")
    try:
        if attach:
            with open(evidence, "rb") as fh:
                r = requests.post(url, data={"payload_json": json.dumps(payload)},
                                  files={"file": (evidence.name, fh)}, timeout=30)
        else:
            r = requests.post(url, json=payload, timeout=30)
        print("Discord HTTP status:", r.status_code)
        if r.status_code >= 300:
            print(r.text[:200])
    except requests.RequestException as exc:
        print("Discord request failed:", type(exc).__name__)


if __name__ == "__main__":
    main()
