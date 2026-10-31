#!/bin/bash
# file-action.sh — quarantine or delete one file named by a scan finding.
#
#   file-action.sh quarantine|delete ABSOLUTE-PATH
#
# Called through polkit from a finding row. The path comes from scanner
# output, so it is validated hard: one absolute path, no control characters,
# an existing regular file (the link itself must not be a symlink), and never
# one of the directories where a "finding" would be a false positive on a
# system file. Quarantine moves the file under /var/lib/greywatch/quarantine
# where the desktop user cannot silently put it back; every action is logged.
set -euo pipefail
GW_DIR="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
DATA="${GW_DATA:-/var/lib/greywatch}"
QUAR="$DATA/quarantine"
LOG="$DATA/helper-actions.log"

[ $# -eq 2 ] || { echo "usage: file-action.sh <quarantine|delete> PATH" >&2; exit 64; }
action="$1"
path="$2"
case "$action" in
    quarantine|delete) ;;
    *) echo "action not allowed" >&2; exit 64;;
esac
[ ${#path} -le 4096 ] || { echo "path too long" >&2; exit 65; }
[ "${path#/}" != "$path" ] || { echo "path must be absolute" >&2; exit 65; }
case "$path" in
    *[[:cntrl:]]*) echo "control character in path" >&2; exit 65;;
esac

target="$(readlink -f -- "$path" 2>/dev/null)" || { echo "no such file" >&2; exit 66; }
[ -f "$target" ] || { echo "not a regular file" >&2; exit 66; }
# A finding is about a file somewhere data lives. A path under these roots
# is far more likely a scanner false positive than an infected file, and
# deleting a system binary through this door would be unrecoverable.
case "$target" in
    /bin/*|/sbin/*|/usr/bin/*|/usr/sbin/*|/lib/*|/lib64/*|/boot/*|\
    /etc/passwd|/etc/shadow|/etc/group|/etc/sudoers|/etc/sudoers.d/*|\
    /var/lib/greywatch/*)
        echo "refusing to touch a system path: $target" >&2; exit 67;;
esac

mkdir -p "$QUAR"
name="$(basename -- "$target")"
stamp="$(date +%Y%m%dT%H%M%S)"

if [ "$action" = quarantine ]; then
    dest="$QUAR/${stamp}-${name}"
    /bin/mv -- "$target" "$dest"
    printf '%s quarantine %s -> %s\n' "$(date -Is)" "$target" "$dest" >> "$LOG"
    printf 'quarantined %s\n' "$dest"
else
    /bin/rm -f -- "$target"
    printf '%s delete %s\n' "$(date -Is)" "$target" >> "$LOG"
    printf 'deleted %s\n' "$target"
fi
