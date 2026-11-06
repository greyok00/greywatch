#!/bin/bash
# restore-quarantine.sh — put a quarantined file back where it was.
#
#   restore-quarantine.sh ORIGINAL-PATH
#
# The old two-argument contract (quarantine folder plus bare file name)
# never matched what the decisions send, so "Put it back" exited 64 in
# production (owner finding, 2026-11-06). The helper now takes the full
# original path, finds its newest quarantined copy in the ledger, and
# moves it home. The destination comes from the ledger's own record,
# never from a hardcoded home directory; every restore is recorded.
set -euo pipefail
MANIFEST="${GW_QUAR_MANIFEST:-/var/lib/greywatch/quarantine.jsonl}"
[ $# -eq 1 ] || { echo "usage: restore-quarantine.sh ORIGINAL-PATH" >&2; exit 64; }
[ -f "$MANIFEST" ] || { echo "no quarantine ledger at $MANIFEST" >&2; exit 66; }
exec python3 - "$MANIFEST" "$(realpath -m "$1")" <<'PY'
import datetime, json, pathlib, shutil, sys

manifest, orig = pathlib.Path(sys.argv[1]), sys.argv[2]
rows = [json.loads(l) for l in manifest.read_text().splitlines()
        if l.strip()]
mine = [r for r in rows if r.get("orig") == orig and r.get("file")]
if not mine:
    print(f"no quarantined copy of {orig} in {manifest}", file=sys.stderr)
    sys.exit(65)
copy = pathlib.Path(mine[-1]["file"])
if not copy.exists():
    print(f"the quarantined copy is gone: {copy}", file=sys.stderr)
    sys.exit(66)
dest = pathlib.Path(orig)
dest.parent.mkdir(parents=True, exist_ok=True)
shutil.move(str(copy), str(dest))
now = datetime.datetime.now(datetime.timezone.utc).isoformat(
    timespec="seconds")
with manifest.open("a") as f:
    f.write(json.dumps({"ts": now, "action": "restored", "orig": orig,
                        "file": str(copy)}) + "\n")
PY
