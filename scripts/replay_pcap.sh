#!/usr/bin/env bash
# Replay a pcap through Suricata (offline mode) and print a quick summary.
# Usage: scripts/replay_pcap.sh pcaps/file.pcap [outdir]
set -eu

PCAP="${1:?usage: $0 <file.pcap> [outdir]}"
OUT="${2:-out/$(basename "${PCAP%.*}")}"

mkdir -p "$OUT"
sudo suricata -c /etc/suricata/suricata.yaml -r "$PCAP" -l "$OUT" -k none

echo
echo "Alerts: $(wc -l < "$OUT/fast.log")"
echo "Top rules:"
awk -F'\\[\\*\\*\\] ' '{print $2}' "$OUT/fast.log" | sort | uniq -c | sort -rn | head -10
