#!/usr/bin/env bash
# Replay a pcap through Suricata (offline mode) and print a quick summary.
# Run from the repo root.
# Usage: [HOME_NET="[192.168.56.111/32]"] scripts/replay_pcap.sh pcaps/file.pcap [outdir]
# Loads custom rules from rules/heimdall.rules when present.
set -eu

PCAP="${1:?usage: $0 <file.pcap> [outdir]}"
OUT="${2:-out/$(basename "${PCAP%.*}")}"
case "$OUT" in
  *..*|/*) echo "outdir must be a relative path under out/"; exit 1 ;;
  out/*) ;;
  *) echo "outdir must be under out/"; exit 1 ;;
esac

ARGS=()
[ -f rules/heimdall.rules ] && ARGS+=(-s rules/heimdall.rules)
[ -n "${HOME_NET:-}" ] && ARGS+=(--set "vars.address-groups.HOME_NET=${HOME_NET}")

sudo rm -rf -- "$OUT"   # Suricata appends to existing logs, so always start clean
mkdir -p "$OUT"
sudo suricata -c /etc/suricata/suricata.yaml -r "$PCAP" -l "$OUT" -k none "${ARGS[@]}"

echo
echo "Alerts (excluding checksum noise): $(grep -vc 'invalid checksum' "$OUT/fast.log" || true)"
echo "Top rules:"
grep -v 'invalid checksum' "$OUT/fast.log" | awk -F'\\[\\*\\*\\] ' '{print $2}' | sort | uniq -c | sort -rn | head -10
