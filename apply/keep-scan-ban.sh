#!/bin/bash
set -euo pipefail
GW_DIR="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
printf '%s\n' "$(date -Is) keep-scan-ban $*" >> "$GW_DIR/data/helper-actions.log"
