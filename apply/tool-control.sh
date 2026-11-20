#!/bin/bash
set -uo pipefail
IFACE="${GW_IFACE:-$(awk 'NR>1 && $2=="00000000" {print $1; exit}' /proc/net/route)}"
[ -n "$IFACE" ] || IFACE=none
UNITS="responderd.service tetragon.service \
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

if [ $# -eq 1 ] && [ "$1" = "scan-all" ]; then
  # One scan at a time. The helper files one request; the resident service
  # runs the five scanners in order behind the one global lock. Nothing
  # here launches a scanner, so a click, a timer and a terminal cannot run
  # a second scan beside the first.
  GW_DIR="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
  exec bash "$GW_DIR/apply/request-scan.sh" full
fi

[ $# -eq 2 ] || { echo "usage: tool-control.sh <start|stop|restart> <unit>; or one-arg <start-all|stop-all|scan-all>" >&2; exit 64; }
action="$1"; unit="$2"
case "$action" in
  start|stop|restart|disable|enable) ;;
  *) echo "action not allowed" >&2; exit 64;;
esac
case "$action:$unit" in
  restart:greywatch.service) ;;
  *:greywatch.service)
    echo "greywatch.service allows restart only" >&2; exit 65 ;;
  *:greywatch-clam-scan.timer)
    echo "the daily clam timer is disabled" >&2; exit 65 ;;
  start:psad.service|stop:psad.service|restart:psad.service) ;;
  start:yara-watch.service|stop:yara-watch.service|restart:yara-watch.service) ;;
  start:greywatch-cve.service|stop:greywatch-cve.service|restart:greywatch-cve.service) ;;
  start:responderd.service|stop:responderd.service|restart:responderd.service) ;;
  start:tetragon.service|stop:tetragon.service|restart:tetragon.service) ;;
  start:fail2ban.service|stop:fail2ban.service|restart:fail2ban.service) ;;
  start:ufw.service|stop:ufw.service|restart:ufw.service) ;;
  start:auditd.service|stop:auditd.service|restart:auditd.service) ;;
  start:apparmor.service|stop:apparmor.service|restart:apparmor.service) ;;
  start:clamav-freshclam.service|stop:clamav-freshclam.service|restart:clamav-freshclam.service) ;;
  start:arpwatch@{iface}.service|stop:arpwatch@{iface}.service|restart:arpwatch@{iface}.service) ;;
  start:arpwatch@${IFACE}.service|stop:arpwatch@${IFACE}.service|restart:arpwatch@${IFACE}.service) ;;
  *) echo "unit not allowed: $unit" >&2; exit 65 ;;
esac
unit="${unit//\{iface\}/$IFACE}"
exec systemctl "$action" "$unit"
