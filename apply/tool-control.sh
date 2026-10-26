#!/bin/bash
set -uo pipefail
IFACE="$(awk 'NR>1 && $2=="00000000" {print $1; exit}' /proc/net/route)"
[ -n "$IFACE" ] || IFACE=none
UNITS="responderd.service tetragon.service clamav-daemon.service \
fail2ban.service ufw.service auditd.service apparmor.service \
greywatch-cve.timer clamav-freshclam.service aide-check.timer \
arpwatch@${IFACE}.service"

if [ $# -eq 1 ] && { [ "$1" = "start-all" ] || [ "$1" = "stop-all" ]; }; then
  action="${1%-all}"
  rc=0
  for unit in $UNITS; do
    systemctl "$action" "$unit" 2>/dev/null || rc=1
  done
  exit "$rc"
fi

[ $# -eq 2 ] || { echo "usage: tool-control.sh <start|stop|restart> <unit>; or one-arg <start-all|stop-all>" >&2; exit 64; }
action="$1"; unit="$2"
case "$action" in
  start|stop|restart) ;;
  *) echo "action not allowed" >&2; exit 64;;
esac
case "$unit" in
  responderd.service|tetragon.service|clamav-daemon.service|\
  fail2ban.service|ufw.service|auditd.service|\
  "arpwatch@${IFACE}.service"|aide-check.timer|apparmor.service|\
  greywatch-cve.timer|clamav-freshclam.service)
    ;;
  *) echo "unit not allowed: $unit" >&2; exit 65;;
esac
exec systemctl "$action" "$unit"
