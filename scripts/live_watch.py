#!/usr/bin/env python3
"""Tail a live Suricata eve.json and post to Discord when something looks suspicious.

Usage: python scripts/live_watch.py out/live/eve.json [--dry-run]
Stop with Ctrl+C.
"""
import json
import os
import sys
import time
from collections import defaultdict
from pathlib import Path

import requests

FANOUT_MIN = 26
COOLDOWN = 120  # seconds, per (host, reason)


def load_env(path=".env"):
    p = Path(path)
    if not p.exists():
        return
    for line in p.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def send(payload, dry):
    if dry:
        print("[dry-run]", json.dumps(payload)[:200])
        return
    url = os.environ.get("DISCORD_WEBHOOK_URL")
    if not url:
        print("DISCORD_WEBHOOK_URL not set, skipping send")
        return
    try:
        r = requests.post(url, json=payload, timeout=10)
        print("Discord HTTP status:", r.status_code)
    except requests.RequestException as exc:
        print("Discord request failed:", type(exc).__name__)


def embed(title, desc, fields, color):
    return {"username": "Heimdall Lite (live)",
            "embeds": [{"title": title[:250], "description": desc,
                        "color": color, "fields": fields,
                        "footer": {"text": "Live mode: streaming Suricata alerts, alert only"}}]}


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    path = Path(sys.argv[1])
    dry = "--dry-run" in sys.argv
    load_env()

    last_sent = {}
    dest_by_min = defaultdict(set)

    print(f"Watching {path} ... Ctrl+C to stop")
    while not path.exists():
        time.sleep(1)
    with open(path) as fh:
        fh.seek(0, os.SEEK_END)
        while True:
            line = fh.readline()
            if not line:
                time.sleep(0.5)
                continue
            try:
                e = json.loads(line)
            except ValueError:
                continue
            kind = e.get("event_type")

            if kind == "alert":
                sig = e["alert"]["signature"]
                sev = e["alert"]["severity"]
                if "invalid checksum" in sig or sig.startswith("SURICATA"):
                    continue
                if sev > 2:
                    continue
                src, dst = e.get("src_ip"), e.get("dest_ip")
                key = (src, "rule")
                now = time.time()
                if now - last_sent.get(key, 0) < COOLDOWN:
                    continue
                last_sent[key] = now
                print(f"RULE ALERT  {src} -> {dst}  {sig}")
                send(embed(f"Heimdall Lite: rule alert from {src}",
                           sig,
                           [{"name": "Source -> destination", "value": f"{src} -> {dst}"},
                            {"name": "Severity", "value": str(sev)}],
                           0xE74C3C if sev == 1 else 0xE67E22), dry)

            elif kind == "flow":
                f = e.get("flow", {})
                start = f.get("start", "")
                if not start:
                    continue
                src, minute = e.get("src_ip"), start[:16]
                dest_by_min[(src, minute)].add(e.get("dest_ip"))
                n = len(dest_by_min[(src, minute)])
                if n < FANOUT_MIN:
                    continue
                key = (src, "fanout")
                now = time.time()
                if now - last_sent.get(key, 0) < COOLDOWN:
                    continue
                last_sent[key] = now
                print(f"FAN-OUT  {src}: {n} destinations in minute {minute}")
                send(embed(f"Heimdall Lite: behavioural alert from {src}",
                           f"{n} distinct destinations contacted within one minute (threshold {FANOUT_MIN}).",
                           [{"name": "Minute", "value": minute}],
                           0xE67E22), dry)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped.")


