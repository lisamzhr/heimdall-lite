#!/usr/bin/env bash
# Replay a pcap through Suricata, then post a Discord summary if it looks suspicious.
# Run from the repo root. Usage: [HOME_NET="[...]"] scripts/run_pipeline.sh pcaps/file.pcap [--dry-run] [--force]
set -eu
PCAP="${1:?usage: $0 <file.pcap> [--dry-run] [--force]}"
shift
OUT="out/$(basename "${PCAP%.*}")"
scripts/replay_pcap.sh "$PCAP" "$OUT"
"$HOME/venv-heimdall/bin/python" scripts/alert_discord.py "$OUT" "$PCAP" "$@"
