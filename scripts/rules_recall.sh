#!/usr/bin/env bash
# Share of Suricata flows carrying at least one alert, for a botnet-only capture.
# Usage: scripts/rules_recall.sh out/<replay-dir>
set -eu
E="${1:?usage: $0 <replay outdir>}/eve.json"
total=$(jq -r 'select(.event_type=="flow") | .flow_id' "$E" | sort -u | wc -l)
anyal=$(jq -r 'select(.event_type=="alert" and (.alert.signature|test("invalid checksum")|not)) | .flow_id' "$E" | sort -u | wc -l)
named=$(jq -r 'select(.event_type=="alert" and (.alert.signature|startswith("SURICATA")|not)) | .flow_id' "$E" | sort -u | wc -l)
echo "flows=$total  flows_with_any_alert=$anyal  flows_with_ET_alert=$named"
