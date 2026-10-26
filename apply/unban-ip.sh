#!/bin/bash
# helper (pkexec only): unban one IP in one jail, strictly validated
set -euo pipefail
[ $# -eq 2 ] || { echo "usage: unban-ip.sh JAIL IP" >&2; exit 64; }
JAIL="$1" IP="$2"
[[ "$JAIL" =~ ^[A-Za-z0-9_-]{1,64}$ ]] || { echo "bad jail" >&2; exit 65; }
[[ $IP =~ ^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])([.](25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}$ ]] || { echo "bad ip" >&2; exit 65; }
exec /usr/bin/fail2ban-client set "$JAIL" unbanip "$IP"
