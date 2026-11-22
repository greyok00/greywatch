#!/bin/bash
set -euo pipefail
GW_DIR="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
[ $# -eq 1 ] || { echo "usage: widen-scan-ban.sh IP" >&2; exit 64; }
IP="$1"
"${PYTHON:-python3}" - "$IP" <<'PY' 2>/dev/null || { echo "bad ip" >&2; exit 65; }
import ipaddress, sys
try:
    ipaddress.ip_address(sys.argv[1])
except ValueError:
    sys.exit(1)
PY
printf '%s\n' "$(date -Is) widen-scan-ban $*" >> "$GW_DIR/data/helper-actions.log"
exec /usr/bin/ufw limit from "$IP"
