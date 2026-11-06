#!/bin/bash
# hardening-arp.sh — close the ARP spoofing door that a single host CAN close.
#
#   hardening-arp.sh
#
# ARP spoofing on a home LAN aims to steal the default route: the attacker
# answers "I am the router" first. A host cannot fix the Wi-Fi switch, but
# it can (1) pin the REAL router's MAC into the neighbour table as a
# permanent entry, and (2) stop announcing its own ARP in ways a spoofer
# abuses (arp_ignore=1, arp_accept=0). The helper never deletes anything,
# derives the router from the live route table, and is idempotent.
set -uo pipefail
IP_BIN="${IP_BIN:-ip}"
SYSCTL_BIN="${SYSCTL_BIN:-sysctl}"
CHANGED=0

note() { echo "hardening-arp: $*"; }

GW="$("$IP_BIN" -4 route show default 2>/dev/null | awk '{print $3; exit}')"
DEV="$("$IP_BIN" -4 route show default 2>/dev/null | awk '{print $5; exit}')"
if [ -z "$GW" ] || [ -z "$DEV" ]; then
    note "no IPv4 default route; nothing to pin"; exit 66
fi
MAC="$("$IP_BIN" neigh show "$GW" 2>/dev/null | awk '{print $5; exit}')"
if [ -z "$MAC" ]; then
    note "no MAC learned yet for gateway $GW; ping it first and rerun"
    "$IP_BIN" neigh show dev "$DEV" 2>/dev/null | head -3
    exit 66
fi
if "$IP_BIN" neigh show dev "$DEV" 2>/dev/null | grep -qF "PERMANENT"; then
    PERM="$("$IP_BIN" neigh show dev "$DEV" 2>/dev/null | grep PERMANENT | awk '{print $1}')"
    if [ "$PERM" = "$GW" ] || echo "$PERM" | grep -qF "$GW"; then
        note "gateway $GW already pinned permanently"
    else
        note "another host is pinned ($PERM); adding router pin for $GW"
    fi
fi
CUR="$("$IP_BIN" neigh get "$GW" dev "$DEV" 2>/dev/null | grep -c lladdr)" || CUR=0
if "$IP_BIN" neigh get "$GW" dev "$DEV" 2>/dev/null | grep -q "PERMANENT"; then
    note "pin for $GW verified"
else
    "$IP_BIN" neigh replace "$GW" lladdr "$MAC" dev "$DEV" nud permanent \
        && { note "pinned gateway $GW at $MAC (dev $DEV)"; CHANGED=1; } \
        || { note "could not pin $GW"; exit 65; }
fi

persist=0
CONF=/etc/sysctl.d/99-greywatch-arp.conf
cur_ignore="$("$SYSCTL_BIN" -n net.ipv4.conf.all.arp_ignore 2>/dev/null)"
cur_accept="$("$SYSCTL_BIN" -n net.ipv4.conf.all.arp_accept 2>/dev/null)"
need_write=0
[ "$cur_ignore" = "1" ] || need_write=1
[ "$cur_accept" = "0" ] || need_write=2
if [ "$need_write" != "0" ]; then
    for f in /proc/sys/net/ipv4/conf/*/arp_ignore; do
        echo 1 > "$f" 2>/dev/null || true
    done
    for f in /proc/sys/net/ipv4/conf/*/arp_accept; do
        echo 0 > "$f" 2>/dev/null || true
    done
    note "arp_ignore=1, arp_accept=0 applied to every interface"
    CHANGED=1
    persist=1
fi
if [ "$persist" = "1" ]; then
    if [ ! -f "$CONF" ] || ! grep -q arp_ignore "$CONF" 2>/dev/null; then
        printf '# greywatch: ARP spoof resistance (2026-11-06)\nnet.ipv4.conf.all.arp_ignore = 1\nnet.ipv4.conf.all.arp_accept = 0\n' > "$CONF" \
            && note "persisted to $CONF" \
            || note "runtime set but persistence failed (sysctl.d unwritable)"
    fi
fi
note "done"
exit 0
