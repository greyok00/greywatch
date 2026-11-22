#!/bin/bash
# block-ip.sh — hold a keeper-chosen address out of the firewall for good.
#
#   block-ip.sh IP
#
# Adds the address to the matching greywatch_blocks nftables set (creating
# the table on first run, with an input hook that drops everything from the
# set), and appends a forever=true line to the blocked-IP ledger so the
# daemon's periodic verification re-arms the block after a reboot. Never
# lifts one: lifting is lift-block.sh's only job. Idempotent; exits 0 when
# the address is verified present.
set -uo pipefail
[ $# -eq 1 ] || { echo "usage: block-ip.sh IP" >&2; exit 64; }
IP="$1"
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
    4) SET="deny_v4" ;;
    6) SET="deny_v6" ;;
    *) echo "bad ip" >&2; exit 65 ;;
esac
NFT_BIN="${NFT_BIN:-nft}"
LEDGER="${GW_BLOCK_LEDGER:-${GREYWATCH_DATA_DIR:-/var/lib/greywatch}/blocked-ips.jsonl}"

if ! "$NFT_BIN" list table inet greywatch_blocks >/dev/null 2>&1; then
    "$NFT_BIN" -f - <<'NFT' >/dev/null 2>&1 || { echo "block-ip: could not create greywatch_blocks" >&2; exit 66; }
add table inet greywatch_blocks
add set inet greywatch_blocks deny_v4 { type ipv4_addr ; flags interval ; auto-merge ; }
add set inet greywatch_blocks deny_v6 { type ipv6_addr ; flags interval ; auto-merge ; }
add chain inet greywatch_blocks in { type filter hook input priority -10 ; policy accept ; }
add rule inet greywatch_blocks in ip saddr @deny_v4 counter drop
add rule inet greywatch_blocks in ip6 saddr @deny_v6 counter drop
NFT
fi
# Deployments created before IPv6 support only have deny_v4. Add the v6
# set and its drop rule rather than refusing every IPv6 forever block.
if [ "$FAMILY" = 6 ] \
   && ! "$NFT_BIN" list set inet greywatch_blocks deny_v6 >/dev/null 2>&1; then
    "$NFT_BIN" add set inet greywatch_blocks deny_v6 "{ type ipv6_addr ; flags interval ; auto-merge ; }" >/dev/null 2>&1 \
      && "$NFT_BIN" add rule inet greywatch_blocks in ip6 saddr @deny_v6 counter drop >/dev/null 2>&1 \
      || { echo "block-ip: could not add the IPv6 block set" >&2; exit 66; }
fi
"$NFT_BIN" add element inet greywatch_blocks "$SET" { "$IP" } >/dev/null 2>&1
if ! "$NFT_BIN" get element inet greywatch_blocks "$SET" "{ $IP }" >/dev/null 2>&1; then
    echo "block-ip: could not add $IP (nftables refused or missing)" >&2
    exit 66
fi
# A forever block supersedes a temporary netguard block. Remove the temp
# element so a later timeout expiry cannot append a release that would
# mask the forever block in the newest-line-wins ledger.
TEMP_SET="scanners_v4"
[ "$FAMILY" = 6 ] && TEMP_SET="scanners_v6"
if "$NFT_BIN" get element inet greywatch_netguard "$TEMP_SET" "{ $IP }" >/dev/null 2>&1; then
    "$NFT_BIN" delete element inet greywatch_netguard "$TEMP_SET" { "$IP" } >/dev/null 2>&1 || true
fi
mkdir -p "$(dirname "$LEDGER")" 2>/dev/null || true
printf '%s\n' "{\"ts\":\"$(date -Is)\",\"kind\":\"block\",\"ip\":\"$IP\",\"source\":\"manual\",\"forever\":true,\"reason\":\"keeper chose to block this address for good\"}" >> "$LEDGER" 2>/dev/null \
    || echo "block-ip: ledger $LEDGER unwritable (block is live, record missing)" >&2
echo "block-ip: $IP is blocked for good (greywatch_blocks)"
exit 0
