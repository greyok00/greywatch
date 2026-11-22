#!/bin/bash
set -euo pipefail
[ $# -eq 2 ] || { echo "usage: unban-ip.sh JAIL IP" >&2; exit 64; }
JAIL="$1" IP="$2"
[[ "$JAIL" =~ ^[A-Za-z0-9_-]{1,64}$ ]] || { echo "bad jail" >&2; exit 65; }
"${PYTHON:-python3}" - "$IP" <<'PY' 2>/dev/null || { echo "bad ip" >&2; exit 65; }
import ipaddress, sys
try:
    ipaddress.ip_address(sys.argv[1])
except ValueError:
    sys.exit(1)
PY
exec /usr/bin/fail2ban-client set "$JAIL" unbanip "$IP"
