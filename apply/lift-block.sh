#!/bin/bash
# lift-block.sh — the ONLY way a greywatch-managed block is released.
#
#   lift-block.sh IP
#
# Asks psad to drop its own auto-block too (best effort: psad may have
# already expired it), removes the address from the greywatch_blocks nft
# set if present, and appends a release line to the blocked-IP ledger so
# the block reviewer stops questioning and verification stops re-arming.
set -uo pipefail
[ $# -eq 1 ] || { echo "usage: lift-block.sh IP" >&2; exit 64; }
IP="$1"
[[ $IP =~ ^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])([.](25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}$ ]] || { echo "bad ip" >&2; exit 65; }
NFT_BIN="${NFT_BIN:-nft}"
PSAD_BIN="${PSAD_BIN:-psad}"
LEDGER="${GW_BLOCK_LEDGER:-/var/lib/greywatch/blocked-ips.jsonl}"

if ! "$PSAD_BIN" --fw-rm-block-ip "$IP" >/dev/null 2>&1; then
    echo "lift-block: psad has no active block for $IP (or psad is absent)"
fi
if "$NFT_BIN" get element inet greywatch_blocks deny_v4 "{ $IP }" >/dev/null 2>&1; then
    "$NFT_BIN" delete element inet greywatch_blocks deny_v4 { "$IP" } >/dev/null 2>&1 \
        && echo "lift-block: $IP removed from greywatch_blocks" \
        || echo "lift-block: could not remove $IP from greywatch_blocks" >&2
else
    echo "lift-block: $IP was not in greywatch_blocks"
fi
mkdir -p "$(dirname "$LEDGER")" 2>/dev/null || true
printf '%s\n' "{\"ts\":\"$(date -Is)\",\"kind\":\"release\",\"ip\":\"$IP\",\"source\":\"manual\",\"reason\":\"keeper lifted the block\"}" >> "$LEDGER" 2>/dev/null \
    || echo "lift-block: ledger $LEDGER unwritable (lift is live, record missing)" >&2
echo "lift-block: $IP released"
exit 0
