#!/bin/bash
# helper (pkexec only): widen a scanner ban = ufw limit from that IP
set -euo pipefail
GW_DIR="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
[ $# -eq 1 ] || { echo "usage: widen-scan-ban.sh IP" >&2; exit 64; }
[[ $1 =~ ^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])([.](25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}$ ]] || { echo "bad ip" >&2; exit 65; }
printf '%s\n' "$(date -Is) widen-scan-ban $*" >> "$GW_DIR/data/helper-actions.log"
exec /usr/bin/ufw limit from "$1"
