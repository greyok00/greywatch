#!/bin/bash
set -euo pipefail
GW_DIR="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
[ $# -eq 1 ] || { echo "usage: tetra-write.sh /etc/tetragon/tetragon.tp.d/NN-name.yaml" >&2; exit 64; }
Y="$1"
[[ "$Y" =~ ^/etc/tetragon/tetragon\.tp\.d/[0-9]{2}-[A-Za-z0-9_.-]{1,60}\.yaml$ ]] || { echo "bad yaml path" >&2; exit 65; }
SRC="$GW_DIR/tmp-payload.yaml"
[ -f "$SRC" ] || { echo "no staged payload" >&2; exit 66; }
cp -a "$Y" "$Y.bak" 2>/dev/null || true
cp -a "$SRC" "$Y"
rm -f "$SRC"
printf '%s\n' "$(date -Is) tetra-write $Y" >> "$GW_DIR/data/helper-actions.log"
echo "installed $Y"
