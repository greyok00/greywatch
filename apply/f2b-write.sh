#!/bin/bash
# helper (pkexec only): write one jail.d + optional filter.d file pair, then
# `fail2ban-client -x reload` (real verify). argv: JAIL LOGPATH MAXRETRY FINDTIME BANTIME FILTER [FAILREGEX]
set -euo pipefail
GW_DIR="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
[ $# -eq 7 ] || [ $# -eq 6 ] || { echo "usage: f2b-write.sh JAIL LOGPATH MAXRETRY FINDTIME BANTIME FILTER [FAILREGEX]" >&2; exit 64; }
JAIL="$1" LOGPATH="$2" MAXRETRY="$3" FINDTIME="$4" BANTIME="$5" FILTER="$6"
FAILREGEX="${7:-}"
[[ "$JAIL" =~ ^[A-Za-z0-9_-]{1,64}$ ]] || { echo "bad jail" >&2; exit 65; }
[[ "$MAXRETRY" =~ ^[0-9]{1,4}$ ]] || { echo "bad maxretry" >&2; exit 65; }
[[ "$FINDTIME" =~ ^[0-9]{1,7}$ ]] || { echo "bad findtime" >&2; exit 65; }
[[ "$BANTIME" =~ ^[0-9]{1,7}$ ]] || { echo "bad bantime" >&2; exit 65; }
JOURNAL_UNIT=""
case "$LOGPATH" in
  # This computer writes service logs to the journal, not to text files.
  # `journal:<unit>` selects fail2ban's systemd backend for ONE validated
  # unit name (owner 2026-10-23: the wizard must offer real sources).
  journal:*)
    JOURNAL_UNIT="${LOGPATH#journal:}"
    [[ "$JOURNAL_UNIT" =~ ^[A-Za-z0-9@._-]{1,64}$ ]] \
      || { echo "bad journal unit" >&2; exit 65; }
    ;;
  *)
    [[ "$LOGPATH" =~ ^[A-Za-z0-9/._-]{2,120}$ ]] \
      || { echo "bad logpath" >&2; exit 65; }
    ;;
esac
[[ "$FILTER" =~ ^[A-Za-z0-9_-]{1,64}$ ]] || { echo "bad filter" >&2; exit 65; }
mkdir -p "/etc/fail2ban/jail.d" "/etc/fail2ban/filter.d"
cp -a "/etc/fail2ban/jail.d/${JAIL}.local" "/etc/fail2ban/jail.d/${JAIL}.local.bak" 2>/dev/null || true
if [ -n "$JOURNAL_UNIT" ]; then
  printf '[%s]\nenabled = true\nfilter  = %s\nbackend = systemd\njournalmatch = _SYSTEMD_UNIT=%s\nmaxretry = %s\nfindtime = %s\nbantime  = %s\n' \
    "$JAIL" "$FILTER" "$JOURNAL_UNIT" "$MAXRETRY" "$FINDTIME" "$BANTIME" \
    > "/etc/fail2ban/jail.d/${JAIL}.local"
else
  printf '[%s]\nenabled = true\nfilter  = %s\nlogpath = %s\nmaxretry = %s\nfindtime = %s\nbantime  = %s\n' \
    "$JAIL" "$FILTER" "$LOGPATH" "$MAXRETRY" "$FINDTIME" "$BANTIME" \
    > "/etc/fail2ban/jail.d/${JAIL}.local"
fi
if [ -n "$FAILREGEX" ]; then
  cp -a "/etc/fail2ban/filter.d/${FILTER}.conf" "/etc/fail2ban/filter.d/${FILTER}.conf.bak" 2>/dev/null || true
  printf 'failregex = ^%s$\nignoreregex =\n' "$FAILREGEX" > "/etc/fail2ban/filter.d/${FILTER}.conf"
fi
printf '%s\n' "$(date -Is) f2b-write $JAIL" >> "$GW_DIR/data/helper-actions.log"
exec /usr/bin/fail2ban-client -x reload
