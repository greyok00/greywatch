#!/bin/bash
# block-review.sh — record the keeper's verdict on a block reviewer question.
#
#   block-review.sh IP keep|lift
#
# "keep" closes the audit trail: the block reviewer never asks about this address
# again. ("lift" reaches here rarely - the card's Lift option calls
# lift-block.sh directly, which both releases the block and records it.)
# Never touches the firewall; verdict only. Idempotent.
set -uo pipefail
[ $# -eq 2 ] || { echo "usage: block-review.sh IP keep|lift" >&2; exit 64; }
IP="$1"
VERDICT="$2"
[[ $IP =~ ^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])([.](25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}$ ]] || { echo "bad ip" >&2; exit 65; }
[ "$VERDICT" = "keep" ] || [ "$VERDICT" = "lift" ] || { echo "verdict must be keep or lift" >&2; exit 65; }
LEDGER="${GW_BLOCK_LEDGER:-/var/lib/greywatch/blocked-ips.jsonl}"
mkdir -p "$(dirname "$LEDGER")" 2>/dev/null || true
printf '%s\n' "{\"ts\":\"$(date -Is)\",\"kind\":\"review\",\"ip\":\"$IP\",\"verdict\":\"$VERDICT\"}" >> "$LEDGER" 2>/dev/null \
    || { echo "block-review: ledger $LEDGER unwritable" >&2; exit 66; }
echo "block-review: verdict $VERDICT recorded for $IP"
exit 0
