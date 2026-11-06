#!/bin/bash
# clear-events.sh — empty the event log at the owner's one press.
#
#   clear-events.sh
#
# The Full logs page reads events.jsonl alone; decisions, scan results and
# quarantine records stay. The daemon re-arms its dedupe index when the
# file shrinks, so no restart is needed after a clear. Truncating is all it
# does, and every clear is logged.
set -euo pipefail
GW_DIR="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
DATA="${GW_DATA:-/var/lib/greywatch}"
[ -f "$DATA/events.jsonl" ] || { echo "no event log at $DATA" >&2; exit 66; }
printf '%s\n' "$(date -Is) clear-events" >> "$DATA/helper-actions.log"
: > "$DATA/events.jsonl"
