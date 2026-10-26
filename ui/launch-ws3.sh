#!/bin/bash
set -u
GW="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
if [ -n "${1:-}" ]; then
  WS_LABEL="$1"
else
  WS_FILE="$GW/data/workspace.json"
  WS_LABEL=3
  if [ -r "$WS_FILE" ]; then
    P=$(sed -n 's/.*"ws"[ :]*\([0-9]\+\).*/\1/p' "$WS_FILE" | head -1)
    [ -n "$P" ] && WS_LABEL="$P"
  fi
fi
WM_IDX=$((WS_LABEL - 1))                        # wmctrl -t is 0-based
APP="$GW/ui/app.py"
export DISPLAY="${DISPLAY:-:0}"

PID=$(pgrep -f "python3 $APP" | head -1)
if [ -z "$PID" ]; then
  python3 "$APP" >/dev/null 2>&1 &              # fresh launch, detached
  sleep 1.5
  PID=$(pgrep -f "python3 $APP" | head -1)
fi
[ -n "$PID" ] || { echo "greywatch app failed to start"; exit 1; }

WIN=""
for _ in $(seq 1 40); do                        # ≤10 s for the window to map
  WIN=$(wmctrl -lp | awk -v p="$PID" '$3==p{print $1; exit}')
  [ -n "$WIN" ] && break
  sleep 0.25
done
[ -n "$WIN" ] || { echo "window not found for pid $PID"; exit 1; }

wmctrl -i -r "$WIN" -t "$WM_IDX"
echo "greywatch (pid $PID, window $WIN) → workspace label $WS_LABEL (wmctrl index $WM_IDX)"
