#!/bin/bash
# helper (pkexec only): restore one file from the responder quarantine
set -euo pipefail
GW_DIR="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
GH="${GW_USER_HOME:-$(dirname "$GW_DIR")}"
[ $# -eq 2 ] || { echo "usage: restore-quarantine.sh QUARDIR FILE" >&2; exit 64; }
Q="$1" F="$2"
[[ "$Q" =~ ^/[A-Za-z0-9_./-]{1,100}$ ]] || { echo "bad quardir" >&2; exit 65; }
[[ "$F" =~ ^[A-Za-z0-9_.-]{1,100}$ ]] || { echo "bad file" >&2; exit 65; }
mkdir -p "$GH"
exec /bin/mv "$Q/$F" "$GH/$F"
