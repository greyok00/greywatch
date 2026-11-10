#!/bin/bash
# baseline-update: refresh a checker baseline so a reviewed-benign warning
# stops re-firing. One argument chooses the tool:
#   rkhunter  - rkhunter --propupd (seconds; blesses the current, reviewed state)
#   aide      - refresh AIDE through the machine's own scoped config, the same
#               one the daily aide-check.service compares against (minutes)
# The previous baseline is never deleted: it is kept beside the new one with
# an .old-YYYYMMDD suffix so the refresh can be undone by hand.
set -uo pipefail

TOOL="${1:-}"
STAMP="$(date +%Y%m%d)"

case "$TOOL" in
  rkhunter)
    DB=/var/lib/rkhunter/db/rkhunter.dat
    [ -f "$DB" ] || { echo "rkhunter baseline not found at $DB" >&2; exit 4; }
    cp -a "$DB" "$DB.old-$STAMP"
    if rkhunter --propupd; then
      echo "rkhunter baseline refreshed: $DB (previous kept as $(basename "$DB").old-$STAMP)"
      exit 0
    fi
    echo "rkhunter --propupd failed" >&2
    exit 5
    ;;
  aide)
    CONF=""
    for c in /etc/aide/aide-scoped.conf /etc/aide/aide.conf; do
      [ -f "$c" ] && CONF="$c" && break
    done
    [ -n "$CONF" ] || { echo "no aide config found" >&2; exit 4; }
    DBDIR="$(dirname "$(ls -d /var/lib/aide 2>/dev/null || echo /var/lib/aide)")"
    if [ -f /var/lib/aide/aide.db ]; then
      cp -a /var/lib/aide/aide.db /var/lib/aide/aide.db.old-$STAMP || true
      MODE=update
    else
      MODE=init
    fi
    if aide --config="$CONF" --$MODE; then
      if [ -f /var/lib/aide/aide.db.new ]; then
        mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
        echo "aide baseline refreshed through $CONF (previous kept as aide.db.old-$STAMP)"
        exit 0
      fi
      echo "aide produced no aide.db.new; baseline untouched" >&2
      exit 5
    fi
    echo "aide --$MODE failed against $CONF" >&2
    exit 5
    ;;
  *)
    echo "usage: baseline-update.sh rkhunter|aide" >&2
    exit 2
    ;;
esac
