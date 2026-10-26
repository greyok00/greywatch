#!/bin/bash
# helper (pkexec only): explicit keep — no-op with a trace
set -euo pipefail
GW_DIR="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
printf '%s\n' "$(date -Is) keep-quarantine $*" >> "$GW_DIR/data/helper-actions.log"
