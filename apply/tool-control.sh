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

if [ $# -eq 1 ] && [ "$1" = "scan-all" ]; then
  # One-shot "run every scanner at once": the deep ClamAV scan, the rootkit
  # scan, the Lynis audit, the AIDE integrity check, and a YARA sweep of the
  # temp folders. All are started concurrently and log to their usual files;
  # the dashboard picks the results up as each one finishes. Each scanner is
  # independent and idempotent, so there is nothing to batch or sequence.
  GW_DIR="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
  GH="${GW_USER_HOME:-$(dirname "$GW_DIR")}"
  mkdir -p "$GH/security-hardening" 2>&1
  rc=0
  # yara-tmp-scan is a USER unit (timer + service in the user's session);
  # plain `systemctl start` targets the system bus where it does not exist
  # and made every scan-all run exit 1. Root reaches the user manager via
  # the machine-qualified form, with a runuser fallback.
  GW_USER_NAME="${GW_USER:-grey}"
  CLAMSCAN_BIN="${CLAMSCAN_BIN:-/usr/bin/clamscan}"
  RKHUNTER_BIN="${RKHUNTER_BIN:-/usr/bin/rkhunter}"
  LYNIS_BIN="${LYNIS_BIN:-/usr/sbin/lynis}"
  RKHUNTER_LOG="${RKHUNTER_LOG:-/var/log/rkhunter.log}"
  LYNIS_LOG="${LYNIS_LOG:-/var/log/lynis.log}"
  SH_DIR="$GH/security-hardening"
  mkdir -p "$SH_DIR" 2>&1
  systemctl --user --machine="${GW_USER_NAME}@.host" start yara-tmp-scan.service 2>/dev/null \
    || runuser -u "$GW_USER_NAME" -- env \
         XDG_RUNTIME_DIR="/run/user/$(id -u "$GW_USER_NAME")" \
         systemctl --user start yara-tmp-scan.service 2>/dev/null \
    || rc=1
  systemctl start aide-check.service 2>/dev/null || rc=1
  # Each scanner refuses to double-run: the lock stays held inside the
  # subshell for the scanner's whole lifetime, so a scan-all clicked while
  # one is in flight skips that scanner instead of piling a second
  # full-home scan on top of the first (the 2026-11-06 CPU-storm finding).
  (
    exec 9>"$SH_DIR/clam-scan.lock"
    flock -n 9 || { echo "clamav already running; skipped" >&2; exit 0; }
    "$CLAMSCAN_BIN" -r --infected \
            --log="$GH/security-hardening/clam-scan.log" \
            "$GH" /tmp /var/tmp >/dev/null 2>&1
  ) &
  (
    exec 9>"$SH_DIR/rkhunter.lock"
    flock -n 9 || { echo "rkhunter already running; skipped" >&2; exit 0; }
    "$RKHUNTER_BIN" --check --sk --report-warnings-only \
            >> "$RKHUNTER_LOG" 2>&1
  ) &
  (
    exec 9>"$SH_DIR/lynis.lock"
    flock -n 9 || { echo "lynis already running; skipped" >&2; exit 0; }
    "$LYNIS_BIN" audit system >> "$LYNIS_LOG" 2>&1
  ) &
  exit "$rc"
fi

[ $# -eq 2 ] || { echo "usage: tool-control.sh <start|stop|restart> <unit>; or one-arg <start-all|stop-all|scan-all>" >&2; exit 64; }
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
