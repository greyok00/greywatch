#!/bin/bash
# request-scan.sh — the only way anything but the daemon asks for a scan.
#
#   request-scan.sh <key>
#
# Files one atomic request for the resident service. The service owns the
# one scan slot: if another scan is already running (including one it did
# not start), this request waits on file and is never a second scanner.
# Keys: full, max-speed (alias of full), scan-all (legacy alias),
#       clamav, rkhunter, lynis, aide, yara-tmp-scan.
set -u
KEY="${1:-full}"
case "$KEY" in
    full|max-speed|scan-all|clamav|rkhunter|lynis|aide|yara-tmp-scan) ;;
    *) echo "not a scan this desk starts: $KEY" >&2; exit 64 ;;
esac
DATA="${GW_DATA_DIR:-/var/lib/greywatch}"
if ! mkdir -p "$DATA" 2>/dev/null; then
    echo "cannot reach the scan service data dir: $DATA" >&2
    exit 65
fi
ID="$(date -u +%Y%m%dT%H%M%S)-$(printf '%04x' $((RANDOM % 65536)))"
TMP="$DATA/.scan-request.$$.json"
if ! printf '{"id":"%s","key":"%s"}\n' "$ID" "$KEY" > "$TMP"; then
    echo "could not write the scan request" >&2
    exit 66
fi
if ! mv -f "$TMP" "$DATA/scan-request.json"; then
    rm -f "$TMP"
    echo "could not publish the scan request" >&2
    exit 66
fi
echo "scan requested: $KEY ($ID)"
