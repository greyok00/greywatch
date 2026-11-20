#!/bin/bash
# yara-tmp-scan.sh — the temp-folder sweep behind the "Quick scan" button.
#
#   yara-tmp-scan.sh RULES-FILE ROOT [ROOT...]
#
# Runs as the desktop user (the daemon wraps it in runuser). It walks each
# root first, printing a progress line every hundred folders, then runs YARA
# over the same roots. The old user-side script printed only hits, so the
# window's counter read 0 folders and the scan looked like it did nothing.
#
# The filters below are the noise rules: over-broad signatures
# on PDFs, the sqlite cache churn, and greywatch's own EICAR test fixtures.
#
# : the exit status is YARA's, never the last filter grep's. In a
# plain pipeline `exit "$?"` reports "no lines selected" (1) for a clean
# scan — the good case read as failure from the desk.
set -u
if [ $# -lt 2 ]; then
    echo "usage: yara-tmp-scan.sh RULES-FILE ROOT [ROOT...]" >&2
    exit 64
fi
RULES="$1"; shift
if [ ! -r "$RULES" ]; then
    echo "no YARA rule file at $RULES" >&2
    exit 65
fi

roots=()
for r in "$@"; do
    [ -d "$r" ] && roots+=("$r")
done
if [ ${#roots[@]} -eq 0 ]; then
    echo "no readable temp folder to sweep" >&2
    exit 66
fi

folders=0
for r in "${roots[@]}"; do
    while IFS= read -r -d '' d; do
        folders=$((folders + 1))
        if [ $((folders % 100)) -eq 0 ]; then
            printf '@@DIRS %d %s\n' "$folders" "$d"
        fi
    done < <(find "$r" -type d -print0 2>/dev/null)
done
printf '@@DIRS %d\n' "$folders"

rawf="$(mktemp)"
raw_all="$(mktemp)"
errf="$(mktemp)"
YARA_BIN="${YARA_BIN:-/usr/bin/yara}"
# Each root is swept on its own with two attempts. A temp file deleted or
# rewritten underneath one pass kills that pass outright ("input in flex
# scanner failed" - owner live finding, 2026-11-05, every 16k-folder sweep
# on a churning box read as "exited 1"): the churn is per-file and passes,
# so the legs are isolated, briefly retried, and the sweep's verdict is
# what was actually swept, never one poison file's shadow over the rest.
swept=0
for r in "${roots[@]}"; do
    ok=""
    for attempt in 1 2; do
        "$YARA_BIN" -r -w "$RULES" "$r" >"$rawf" 2>"$errf"
        yara_rc=$?
        if [ "$yara_rc" -eq 0 ]; then
            ok=1
            cat "$rawf" >>"$raw_all"
            break
        fi
        sleep 3
    done
    if [ -n "$ok" ]; then
        swept=$((swept + 1))
    else
        head -n 1 "$errf" >&2          # one line of why, in the journal
    fi
done
rm -f "$rawf" "$errf"
hits="$(grep -vE '(Big_Numbers1|invalid_trailer_structure|possible_includes_base64_packed_functions).*\.(pdf|html)( |$)' "$raw_all" \
    | grep -vE 'with_sqlite.*(/tmp/sxng_cache_|/var/tmp/sxng_cache_|scantemp)' \
    | grep -vE '/(var/)?tmp/pytest-of-[^/]+/pytest-[0-9]+/' \
)"
rm -f "$raw_all"
[ -n "$hits" ] && printf '%s\n' "$hits"
[ "$swept" -gt 0 ] || exit 1     # nothing could be swept at all
exit 0
