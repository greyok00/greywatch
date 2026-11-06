#!/bin/bash
# block-ip.sh — hold a keeper-chosen address out of the firewall for good.
#
#   block-ip.sh IP
#
# Adds the address to the greywatch_blocks nftables set (creating the table
# on first run, with an input hook that drops everything from the set), and
# appends a forever=true line to the blocked-IP ledger so the daemon's
# periodic verification re-arms the block after a reboot. Never lifts one:
# lifting is lift-block.sh's only job. Idempotent; exits 0 when the address
# is verified present.
set -uo pipefail
[ $# -eq 1 ] || { echo "usage: block-ip.sh IP" >&2; exit 64; }
IP="$1"
[[ $IP =~ ^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])([.](25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}$ ]] || { echo "bad ip" >&2; exit 65; }
NFT_BIN="${NFT_BIN:-nft}"
LEDGER="${GW_BLOCK_LEDGER:-/var/lib/greywatch/blocked-ips.jsonl}"

if ! "$NFT_BIN" list table inet greywatch_blocks >/dev/null 2>&1; then
    "$NFT_BIN" -f - <<'NFT' >/dev/null 2>&1 || { echo "block-ip: could not create greywatch_blocks" >&2; exit 66; }
add table inet greywatch_blocks
add set inet greywatch_blocks deny_v4 { type ipv4_addr ; flags interval ; auto-merge ; }
add chain inet greywatch_blocks in { type filter hook input priority -10 ; policy accept ; }
add rule inet greywatch_blocks in ip saddr @deny_v4 counter drop
NFT
fi
"$NFT_BIN" add element inet greywatch_blocks deny_v4 { "$IP" } >/dev/null 2>&1
if ! "$NFT_BIN" get element inet greywatch_blocks deny_v4 "{ $IP }" >/dev/null 2>&1; then
    echo "block-ip: could not add $IP (nftables refused or missing)" >&2
    exit 66
fi
mkdir -p "$(dirname "$LEDGER")" 2>/dev/null || true
printf '%s\n' "{\"ts\":\"$(date -Is)\",\"kind\":\"block\",\"ip\":\"$IP\",\"source\":\"manual\",\"forever\":true,\"reason\":\"keeper chose to block this address for good\"}" >> "$LEDGER" 2>/dev/null \
    || echo "block-ip: ledger $LEDGER unwritable (block is live, record missing)" >&2
echo "block-ip: $IP is blocked for good (greywatch_blocks)"
exit 0
