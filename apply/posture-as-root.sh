#!/bin/bash
# The Security Center's root re-read (owner 2026-11-16): run the same
# posture computation the CLI runs, in the root context where the Lynis
# report, the AppArmor profile table and the CVE announced-ledger are
# readable, then leave the result user-readable again (the daemon's
# root:grey 0640 convention, events.jsonl's shape).
set -uo pipefail
GW_DIR="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"

cd "$GW_DIR" || exit 70
python3 cli.py posture >/dev/null 2>&1
rc=$?

F="$(python3 - <<'PY'
import gwpaths
print(gwpaths.data_dir() / "posture.json")
PY
)"
if [ -f "$F" ]; then
    chown root:grey "$F" 2>/dev/null
    chmod 0640 "$F" 2>/dev/null
fi
exit "$rc"
