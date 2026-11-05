#!/bin/bash
set -euo pipefail
GW_DIR="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
[ $# -eq 4 ] || { echo "usage: arpwrite.sh IFACE RUNAS ARGS PCAPFILTER" >&2; exit 64; }
IFACE="$1" RUNAS="$2" ARGS="$3" PCF="$4"
[[ "$IFACE" =~ ^[a-z0-9.]{2,15}$ ]] || { echo "bad iface" >&2; exit 65; }
[[ "$RUNAS" =~ ^[A-Za-z0-9_-]{1,16}$ ]] || { echo "bad runas" >&2; exit 65; }
OK=1
IFS=" " read -ra TOK <<< "$ARGS"
for tk in "${TOK[@]}"; do
  case "$tk" in -N|-p|-l|-d) ;; *) OK=0 ;; esac
done
[ "$OK" = 1 ] || { echo "bad args" >&2; exit 65; }
if [ -n "$PCF" ]; then
  FILTER_RE='^[A-Za-z0-9][A-Za-z0-9 ._:()-]{0,198}$'
  [[ $PCF =~ $FILTER_RE ]] || { echo "bad filter" >&2; exit 65; }
fi
mkdir -p "/etc/arpwatch"
cp -a "/etc/arpwatch/${IFACE}.iface" "/etc/arpwatch/${IFACE}.iface.bak" 2>/dev/null || true
printf 'RUNAS="%s"\nARGS="%s"\nPCAP_FILTER="%s"\n' "$RUNAS" "$ARGS" "$PCF" > "/etc/arpwatch/${IFACE}.iface"
printf '%s\n' "$(date -Is) arpwrite $IFACE" >> "$GW_DIR/data/helper-actions.log"
exec /bin/systemctl -q enable --now "arpwatch@$IFACE.service"
