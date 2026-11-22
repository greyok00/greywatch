#!/bin/bash
# netguard.sh — arm the host-local inbound sweep sensor and temporary
# block set.
#
#   netguard.sh [arm|status|disarm]
#
# The sensor chain only LOGS packets. It contains no accept/drop/return
# verdict, so UFW and every other input chain still decide every packet.
# The separate block chain (priority -10) drops only sources the daemon
# explicitly placed in scanners_v4 or scanners_v6; those entries carry a
# timeout and expire in the kernel.
#
# Idempotent: a rerun that finds the sensor prefix and both scanner sets
# changes nothing. --reload is deliberately not offered: recreating the
# table would silently clear live temporary blocks.
set -uo pipefail
NFT_BIN="${NFT_BIN:-nft}"
TABLE="inet greywatch_netguard"
ACTION="${1:-arm}"

note() { echo "netguard: $*"; }

case "$ACTION" in
status)
    if "$NFT_BIN" list table $TABLE >/dev/null 2>&1; then
        note "armed"
        exit 0
    fi
    note "not armed"
    exit 1
    ;;
disarm)
    if "$NFT_BIN" delete table $TABLE >/dev/null 2>&1; then
        note "disarmed (temporary blocks cleared)"
    else
        note "was not armed"
    fi
    exit 0
    ;;
arm) ;;
*)
    echo "usage: netguard.sh [arm|status|disarm]" >&2
    exit 64
    ;;
esac

if "$NFT_BIN" list table $TABLE >/dev/null 2>&1; then
    CURRENT="$("$NFT_BIN" list table $TABLE 2>/dev/null || true)"
    # Use case, not printf|grep: grep -q exits early and pipefail can turn
    # SIGPIPE on the writer into a false "not armed" (the helper would then
    # rebuild the table and silently drop live temporary blocks).
    case "$CURRENT" in
        *"GW-SCAN:"*)
            case "$CURRENT" in
                *scanners_v4*)
                    case "$CURRENT" in
                        *scanners_v6*)
                            note "already armed"
                            exit 0
                            ;;
                    esac
                    ;;
            esac
            ;;
    esac
    note "incomplete table found; recreating (active temporary blocks clear)"
    "$NFT_BIN" delete table $TABLE >/dev/null 2>&1 || true
fi

if ! "$NFT_BIN" -f - <<'NFT' >/dev/null 2>&1
add table inet greywatch_netguard
add set inet greywatch_netguard scanners_v4 { type ipv4_addr ; flags timeout ; }
add set inet greywatch_netguard scanners_v6 { type ipv6_addr ; flags timeout ; }
add chain inet greywatch_netguard input { type filter hook input priority -20 ; policy accept ; }
add chain inet greywatch_netguard block { type filter hook input priority -10 ; policy accept ; }
add rule inet greywatch_netguard input iifname != "lo" ct state new limit rate 120/minute burst 240 packets log level warn prefix "GW-SCAN: "
add rule inet greywatch_netguard input iifname != "lo" ct state invalid meta l4proto tcp limit rate 120/minute burst 240 packets log level warn prefix "GW-STEALTH: "
add rule inet greywatch_netguard block ip saddr @scanners_v4 counter drop
add rule inet greywatch_netguard block ip6 saddr @scanners_v6 counter drop
NFT
then
    note "could not create $TABLE (nftables missing or refused)"
    exit 66
fi

VISIBLE="$("$NFT_BIN" list table $TABLE 2>/dev/null || true)"
case "$VISIBLE" in
    *"GW-SCAN:"*) ;;
    *)
        note "table was created but the sensor rule is not visible"
        exit 66
        ;;
esac
note "armed: inbound sensor + temporary block set"
exit 0
