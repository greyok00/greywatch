#!/bin/bash
# config-write: stage one allowlisted tool config back to its real path.
#
#   config-write.sh <conf-key> <staged-file>
#
# The key must be in this script's own allowlist - the UI maps each tool's
# config to the same key. The staged file is validated for being present
# and non-empty (line-level key checking lives in the app's validator,
# which refuses the write before this lane is ever asked). The target is
# rewritten atomically and the previous file is kept beside it with an
# .old-YYYYMMDD suffix, so every write can be undone by hand.
set -uo pipefail

[ $# -eq 2 ] || { echo "usage: config-write.sh <conf-key> <staged-file>" >&2; exit 64; }
KEY="$1"; STAGED="$2"

[ -f "$STAGED" ] || { echo "staged file not found: $STAGED" >&2; exit 3; }
[ -s "$STAGED" ] || { echo "staged config is empty - refusing to blank a config" >&2; exit 5; }

case "$KEY" in
  rkhunter-default) TARGET=/etc/default/rkhunter;;
  rkhunter-conf)    TARGET=/etc/rkhunter.conf;;
  psad)             TARGET=/etc/psad/psad.conf;;
  aide)             TARGET=/etc/aide/aide.conf;;
  freshclam)        TARGET=/etc/clamav/freshclam.conf;;
  clamd)            TARGET=/etc/clamav/clamd.conf;;
  arpwatch-default) TARGET=/etc/default/arpwatch;;
  lynis)            TARGET=/etc/lynis/lynis.cfg;;
  *) echo "config key not allowed: $KEY" >&2; exit 65;;
esac

[ -f "$TARGET" ] || { echo "config not found at its path: $TARGET" >&2; exit 4; }

if cmp -s "$STAGED" "$TARGET"; then
  echo "no change: $TARGET already holds exactly this content"
  exit 0
fi

STAMP="$(date +%Y%m%d)"
cp -a "$TARGET" "$TARGET.old-$STAMP" || {
  echo "the backup failed - nothing was written" >&2; exit 6; }

if install -m 0644 "$STAGED" "$TARGET.greywatch-new.$$" \
     && mv "$TARGET.greywatch-new.$$" "$TARGET"; then
  echo "wrote $TARGET (previous kept as $(basename "$TARGET").old-$STAMP)"
  exit 0
fi
echo "the write did not land - the previous file is untouched" >&2
exit 7
