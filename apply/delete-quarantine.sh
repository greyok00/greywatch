#!/bin/bash
# delete-quarantine.sh — purge what was quarantined (owner 2026-11-06:
# "i want to be able to block and delete them and forever block them").
#
#   delete-quarantine.sh ORIGINAL-PATH
#
# Reads the quarantine ledger, removes the newest quarantined copy of
# the original path, and records the deletion. A second purge of the
# same path is a clean success; a path that was never quarantined is an
# error. The destination comes from the ledger itself, never from a
# hardcoded home directory.
set -euo pipefail
MANIFEST="${GW_QUAR_MANIFEST:-/var/lib/greywatch/quarantine.jsonl}"
[ $# -eq 1 ] || { echo "usage: delete-quarantine.sh ORIGINAL-PATH" >&2; exit 64; }
[ -f "$MANIFEST" ] || { echo "no quarantine ledger at $MANIFEST" >&2; exit 66; }
exec python3 - "$MANIFEST" "$(realpath -m "$1")" <<'PY'
import datetime, json, pathlib, sys

manifest, orig = pathlib.Path(sys.argv[1]), sys.argv[2]
rows = [json.loads(l) for l in manifest.read_text().splitlines()
        if l.strip()]
mine = [r for r in rows if r.get("orig") == orig]
if not mine:
    sys.exit(65)                     # never quarantined here
if mine[-1].get("action") == "deleted":
    sys.exit(0)                      # already purged: idempotent
if mine[-1].get("action") == "restored":
    # the owner put this file back; there is nothing locked away to purge
    print(f"nothing to delete: {orig} was put back", file=sys.stderr)
    sys.exit(65)
copy = pathlib.Path(mine[-1]["file"])
copy.unlink(missing_ok=True)
now = datetime.datetime.now(datetime.timezone.utc).isoformat(
    timespec="seconds")
with manifest.open("a") as f:
    f.write(json.dumps({"ts": now, "action": "deleted", "orig": orig})
            + "\n")
PY
