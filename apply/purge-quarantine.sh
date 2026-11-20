#!/bin/bash
# purge-quarantine.sh — delete EVERY quarantined copy on record
# (owner 2026-11-12: "still can't delete permanently the docs.zip
# quarantine. attempted dozens of times"). The per-card delete removed
# one original path's newest copy; hundreds of copies from dead test
# dirs stayed. This purges all of them: every ledger copy is unlinked,
# every row is marked deleted, and the result is counted and said.
#
#   purge-quarantine.sh [ORIGINAL-PATH]
#
# With an argument, only that original path's copies are purged; with
# no argument, everything the ledger records. Dry-run impossible by
# construction: this helper exists to delete, and the app's own confirm
# dialog stands before it.
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
# The sweep directory is the manifest's OWN directory — never a $HOME
# fallback. A test fixture manifest in /tmp must be able to touch
# nothing but its own recorded file paths; sweeping a guessed $HOME
# directory from another manifest's context is exactly how a real
# purge crossed into unrelated data (2026-11-12, confessed: a test
# purge swept the live quarantine dir). The glob below only runs when
# QDIR is the manifest's real sibling directory.
QDIR="$(dirname "$(realpath "$MANIFEST" 2>/dev/null || echo "$MANIFEST")")/quarantine"
FALLBACK_QDIR="${HOME}/security-hardening/quarantine"
[ -d "$QDIR" ] || QDIR=""   # no manifest sibling → no glob sweep at all

exec python3 - "$MANIFEST" "$QDIR" "$@" <<'PY'
import datetime, json, pathlib, sys

manifest = pathlib.Path(sys.argv[1])
qdir = pathlib.Path(sys.argv[2])
only_orig = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] else None

if not manifest.exists():
    print("no quarantine ledger at", manifest, file=sys.stderr)
    sys.exit(66)

rows = [json.loads(l) for l in manifest.read_text().splitlines()
        if l.strip()]
origs = {}
for r in rows:
    action = r.get("action")
    if action == "deleted":
        continue
    orig = r.get("orig") or ""
    if not orig:
        continue
    origs.setdefault(orig, []).append(r)

targets = origs
if only_orig is not None:
    orig = pathlib.Path(only_orig).resolve()
    if str(orig) not in origs:
        print(f"nothing quarantined on record for {orig}",
              file=sys.stderr)
        sys.exit(65)
    targets = {str(orig): origs[str(orig)]}

now = datetime.datetime.now(datetime.timezone.utc).isoformat(
    timespec="seconds")
deleted, missing = 0, 0
out = []
for orig, rs in targets.items():
    for r in rs:
        copy = r.get("file") and pathlib.Path(r["file"])
        if copy is None:
            continue
        try:
            if copy.exists():
                copy.unlink()
                deleted += 1
            else:
                missing += 1
        except OSError as e:
            print(f"could not remove {copy}: {e}", file=sys.stderr)
    out.append({"ts": now, "action": "deleted", "orig": orig})

# Leftover sweep (the manifest may have been trimmed and no longer
# know a copy): ONLY inside the manifest's own sibling directory, and
# ONLY for the full purge (no path argument). A fixture manifest whose
# dir has no quarantine subdir sweeps NOTHING.
if only_orig is None and qdir and pathlib.Path(qdir).is_dir():
    stem_set = set()
    for orig, rs in targets.items():
        for r in rs:
            stem = (r.get("file") or "").split("/")[-1]
            stem = stem.rsplit(".", 2)[0] if stem.count(".") >= 2 else stem
            stem_set.add(stem)
    for f in pathlib.Path(qdir).glob("*"):
        stem = f.name.rsplit(".", 2)[0] if f.name.count(".") >= 2 else f.name
        if stem and stem in stem_set and f.exists():
            try:
                f.unlink()
                deleted += 1
            except OSError:
                pass

with manifest.open("a") as f:
    for row in out:
        f.write(json.dumps(row) + "\n")

print(f"purged {deleted} quarantined cop{'y' if deleted == 1 else 'ies'}"
      + (f"; {missing} were already gone" if missing else ""))
PY
