#!/bin/bash
set -euo pipefail
[ $# -ge 3 ] || { echo "usage: drop-listener.sh ACTION DIRECTION FROM [PORTPROTO...]" >&2; exit 64; }
for a in "$1" "$2"; do
  [[ "$a" =~ ^(allow|deny|reject|limit|in|out)$ ]] || { echo "bad token: $a" >&2; exit 65; }
done
FROM="$3"
"${PYTHON:-python3}" - "$FROM" <<'PY' 2>/dev/null || { echo "bad ip" >&2; exit 65; }
import ipaddress, sys
try:
    ipaddress.ip_address(sys.argv[1])
except ValueError:
    sys.exit(1)
PY
PORTS=("${@:4}")
for p in "${PORTS[@]}"; do
  [ -z "$p" ] && continue
  [[ "$p" =~ ^(port[[:space:]][0-9]{1,5}[[:space:]]proto[[:space:]](tcp|udp|icmp))$ || "$p" =~ ^(comment[[:space:]][A-Za-z0-9._-]{1,64})$ ]] \
    || { echo "bad port/comment: $p" >&2; exit 65; }
done
exec /usr/bin/ufw "$1" "$2" from "$FROM" "${PORTS[@]}"
