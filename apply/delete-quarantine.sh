#!/bin/bash
# delete-quarantine.sh — purge what was quarantined (owner 2026-11-06:
# "i want to be able to block and delete them and forever block them";
# owner 2026-11-12: "still can't delete permanently the docs.zip
# quarantine. attempted dozens of times") — the dozens of attempts were
# real: the old law removed the NEWEST quarantined copy of one original
# path, while older copies of the same path (from re-runs, renamed
# temporary homes) stayed on disk and the same file kept asking again.
# The delete now purges EVERY quarantined copy of that original path.
#
#   delete-quarantine.sh ORIGINAL-PATH
#
# Reads the quarantine ledger, removes every quarantined copy of the
# original path, and records the deletion. A second purge of the same
# path is a clean success; a path that was never quarantined is an
# error. The destinations come from the ledger itself, never from a
# hardcoded home directory. (Everything-under-the-ledger bulk purge is
# purge-quarantine.sh.)
set -euo pipefail

# A test run must never write the live ledger: 580 pytest scratch rows
# landed here on 2026-10-27. Tests name their own manifest; a pytest
# process that does not is refused.
if [ -n "${PYTEST_CURRENT_TEST:-}" ] && [ -z "${GW_QUAR_MANIFEST:-}" ] \
        && [ "${GREYWATCH_ALLOW_LIVE_DATA:-0}" != "1" ]; then
    echo "refusing to touch the live quarantine ledger from a test run" >&2
    exit 78
fi
MANIFEST="${GW_QUAR_MANIFEST:-${GREYWATCH_DATA_DIR:-/var/lib/greywatch}/quarantine.jsonl}"
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
if mine[-1].get("action") == "deleted" and not any(
        r.get("file") for r in mine if r.get("action") != "deleted"
        and pathlib.Path(r["file"]).exists()):
    sys.exit(0)                      # already purged: idempotent
if mine[-1].get("action") == "restored":
    # the owner put this file back; there is nothing locked away to purge
    print(f"nothing to delete: {orig} was put back", file=sys.stderr)
    sys.exit(65)
removed = 0
now = datetime.datetime.now(datetime.timezone.utc).isoformat(
    timespec="seconds")
# Every quarantined COPY of this original goes — the newest alone kept
# the same file asking again from an older copy (the owner's dozens of
# failed deletes, 2026-11-12).
seen_copies = set()
for r in mine:
    f = r.get("file")
    if not f or r.get("action") in ("restored", "deleted"):
        continue
    copy = pathlib.Path(f)
    if copy in seen_copies:
        continue
    seen_copies.add(copy)
    try:
        if copy.exists():
            copy.unlink()
            removed += 1
    except OSError as e:
        print(f"could not remove {copy}: {e}", file=sys.stderr)
with manifest.open("a") as fh:
    fh.write(json.dumps({"ts": now, "action": "deleted", "orig": orig})
             + "\n")
print(f"removed {removed} quarantined cop{'y' if removed == 1 else 'ies'} "
      f"of {pathlib.Path(orig).name}") if removed else None
PY
