#!/bin/bash
# netguard-block.sh — temporarily hold one external scanner out.
#
#   netguard-block.sh IP [TTL_SECONDS]
#
# Adds the address to the matching netguard timeout set (scanners_v4 or
# scanners_v6) and records the block in the same ledger the dashboard
# already reads. The address leaves the kernel set when its timeout
# expires; blockledger.active_blocks() ignores the expired record, so the
# UI agrees with the firewall.
set -uo pipefail
[ $# -ge 1 ] && [ $# -le 2 ] || {
    echo "usage: netguard-block.sh IP [TTL_SECONDS]" >&2; exit 64; }
IP="$1"
TTL="${2:-3600}"
[[ $TTL =~ ^[0-9]+$ ]] && [ "$TTL" -ge 60 ] && [ "$TTL" -le 86400 ] \
    || { echo "bad ttl (60..86400 seconds)" >&2; exit 65; }
PY="${PYTHON:-python3}"
FAMILY="$("$PY" - "$IP" <<'PY' 2>/dev/null
import ipaddress, sys
try:
    print(ipaddress.ip_address(sys.argv[1]).version)
except ValueError:
    sys.exit(1)
PY
)" || { echo "bad ip" >&2; exit 65; }
case "$FAMILY" in
    4) SET="scanners_v4" ;;
    6) SET="scanners_v6" ;;
    *) echo "bad ip" >&2; exit 65 ;;
esac

NFT_BIN="${NFT_BIN:-nft}"
HELPER="${GW_NETGUARD_HELPER:-$(dirname "$0")/netguard.sh}"
LEDGER="${GW_BLOCK_LEDGER:-${GREYWATCH_DATA_DIR:-/var/lib/greywatch}/blocked-ips.jsonl}"

# Ensure the sensor/table exists. netguard.sh is a no-op when it is complete;
# if the table is incomplete it repairs it, which is better than leaving a
# block helper that cannot add anything.
"$HELPER" arm >/dev/null 2>&1 \
    || { echo "netguard-block: sensor table could not be armed" >&2; exit 66; }

"$NFT_BIN" add element inet greywatch_netguard "$SET" \
    "{ $IP timeout ${TTL}s }" >/dev/null 2>&1
if ! "$NFT_BIN" get element inet greywatch_netguard "$SET" \
        "{ $IP }" >/dev/null 2>&1; then
    echo "netguard-block: nftables refused $IP" >&2
    exit 66
fi

mkdir -p "$(dirname "$LEDGER")" 2>/dev/null || true
NOW="$(date -u +%s)"
EXPIRES="$(date -u -d "@$((NOW + TTL))" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || true)"
REASON="${GW_NETGUARD_REASON:-inbound scan against this host}"
printf '%s\n' "{\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"kind\":\"block\",\"ip\":\"$IP\",\"source\":\"net-watch\",\"forever\":false,\"ttl_s\":$TTL,\"expires_at\":\"$EXPIRES\",\"reason\":\"$REASON\"}" \
    >> "$LEDGER" 2>/dev/null \
    || echo "netguard-block: ledger $LEDGER unwritable (block is live, record missing)" >&2
echo "netguard-block: $IP blocked for ${TTL}s (netguard $SET)"
exit 0
