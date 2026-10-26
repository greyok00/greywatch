#!/bin/bash
# helper (pkexec only): keep the ban — trace only
set -euo pipefail
GW_DIR="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
printf '%s\n' "$(date -Is) keep-scan-ban $*" >> "$GW_DIR/data/helper-actions.log"
