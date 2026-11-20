#!/bin/bash
# patch-packages.sh — install the fixed versions of named installed packages.
#
#   patch-packages.sh PACKAGE [PACKAGE...]
#
# Run through the polkit helper gate. Only package names are accepted; a
# name that is not installed is refused. apt performs the upgrade, and the
# caller records the from/to versions in the patch ledger.
set -uo pipefail
APT_GET="${APT_GET_BIN:-/usr/bin/apt-get}"
DPKG_QUERY="${DPKG_QUERY_BIN:-/usr/bin/dpkg-query}"

if [ $# -lt 1 ]; then
    echo "usage: patch-packages.sh PACKAGE [PACKAGE...]" >&2
    exit 64
fi

rc=0
# The upgrade-all lane is exactly one argument. A cached package name can
# never smuggle it in beside real names (a first "--all" among targets
# used to reach apt as an option).
if [ $# -eq 1 ] && [ "${1:-}" = "--all" ]; then
    log=$(mktemp /tmp/greywatch-patch.XXXXXX)
    if DEBIAN_FRONTEND=noninteractive "$APT_GET" -y upgrade >"$log" 2>&1; then
        echo "installed all available updates"
    else
        echo "failed: $(tail -n 1 "$log" 2>/dev/null)" >&2
        rc=1
    fi
    rm -f "$log"
    exit "$rc"
fi
valid=()
declare -A before_version=()
for pkg in "$@"; do
    # A Debian package name starts with a lower-case letter or digit and
    # carries only lower-case letters, digits, '+', '.', '-'. A leading
    # '-' is refused so apt-get can never read a name as an option.
    case "$pkg" in
        ''|[!a-z0-9]*|*[!a-z0-9+.-]*)
            echo "invalid package name: $pkg" >&2
            rc=2
            continue
            ;;
    esac
    if ! "$DPKG_QUERY" -W "$pkg" >/dev/null 2>&1; then
        echo "not installed: $pkg" >&2
        rc=2
        continue
    fi
    before_version["$pkg"]=$("$DPKG_QUERY" -W -f='${Version}' "$pkg" \
        2>/dev/null)
    valid+=("$pkg")
done

# One apt process for every validated name: apt resolves and orders the
# set itself, and a few hundred names cannot overrun the caller's budget
# the way one process per package could.
if [ "${#valid[@]}" -gt 0 ]; then
    log=$(mktemp /tmp/greywatch-patch.XXXXXX)
    if DEBIAN_FRONTEND=noninteractive "$APT_GET" -y install \
            --only-upgrade -- "${valid[@]}" >"$log" 2>&1; then
        for pkg in "${valid[@]}"; do
            after=$("$DPKG_QUERY" -W -f='${Version}' "$pkg" 2>/dev/null)
            echo "patched $pkg ${before_version[$pkg]} -> $after"
        done
    else
        echo "failed: $(tail -n 1 "$log" 2>/dev/null)" >&2
        rc=1
    fi
    rm -f "$log"
fi
exit "$rc"
