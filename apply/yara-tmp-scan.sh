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
# The filters below are the 2026-09-23 noise rules: over-broad signatures
# on PDFs, the sqlite cache churn, and greywatch's own EICAR test fixtures.
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

/usr/bin/yara -r -w "$RULES" "${roots[@]}" 2>/dev/null \
    | grep -vE '(Big_Numbers1|invalid_trailer_structure|possible_includes_base64_packed_functions).*\.(pdf|html)( |$)' \
    | grep -vE 'with_sqlite.*(/tmp/sxng_cache_|/var/tmp/sxng_cache_|scantemp)' \
    | grep -vE '/(var/)?tmp/pytest-of-[^/]+/pytest-[0-9]+/'
exit "$?"
