#!/bin/bash
# helper (pkexec only): install one YARA rule under greywatch/ rules dir with
# backup + index update. argv: RULENAME (the YAML body is staged by the wizard)
set -euo pipefail
GW_DIR="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
[ $# -eq 1 ] || { echo "usage: yara-write.sh RULENAME" >&2; exit 64; }
N="$1"
[[ "$N" =~ ^[A-Za-z0-9_-]{1,64}$ ]] || { echo "bad rule name" >&2; exit 65; }
DEST="${GW_USER_HOME:-$(dirname "$GW_DIR")}/yara-rules/${N}.yar"
SRC="$GW_DIR/tmp-payload.yar"
[ -f "$SRC" ] || { echo "no staged payload" >&2; exit 66; }
cp -a "$DEST" "$DEST.bak" 2>/dev/null || true
mv "$SRC" "$DEST"
printf '%s\n' "$(date -Is) yara-write $N" >> "$GW_DIR/data/helper-actions.log"
echo "installed $DEST"
