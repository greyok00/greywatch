#!/bin/bash
# psad-tune.sh — feed psad on the firewall that is actually running, and arm
# its auto-block so a sustained attack is stopped without hurting the owner.
#
#   psad-tune.sh
#
# What it does, in the order the owner's constraints demand (2026-11-06,
# "no false positives but it should be able to detect and prevent"):
#   1. Makes inbound traffic VISIBLE: greywatch's own nftables only hooked
#      output traffic, so nobody ever saw an inbound sweep. A dedicated
#      greywatch_psad table logs new inbound connections, rate-limited so a
#      flood cannot drown the log.
#   2. Arms psad's auto-block at danger level 5 ONLY (sustained attack),
#      with the owner's own LAN range and gateway whitelisted first, so a
#      house device can never be blocked by mistake.
#   3. UFW, when it IS active, gets logging medium so psad is fed.
# Every change is echoed; a rerun changes nothing. Binaries and paths are
# env-overridable so the helper can be verified from its tree without root.
set -uo pipefail
NFT_BIN="${NFT_BIN:-nft}"
PSAD_CONF="${PSAD_CONF:-/etc/psad/psad.conf}"
PSAD_WHITELIST="${PSAD_WHITELIST:-/etc/psad/psadwhitelist}"
UFW_BIN="${UFW_BIN:-ufw}"
SYSTEMCTL_BIN="${SYSTEMCTL_BIN:-systemctl}"
SYSCTL_BIN="${SYSCTL_BIN:-sysctl}"
IP_BIN="${IP_BIN:-ip}"
KERN_LOG="${KERN_LOG:-/var/log/kern.log}"
CHANGED=0

note() { echo "psad-tune: $*"; }

# 1. the inbound log chain -----------------------------------------------
if "$NFT_BIN" list table inet greywatch_psad >/dev/null 2>&1; then
    note "nftables greywatch_psad table already present"
else
    "$NFT_BIN" -f - <<'NFT' || { note "nftables table creation failed"; exit 65; }
add table inet greywatch_psad
add chain inet greywatch_psad in { type filter hook input priority -15 ; policy accept ; }
add rule inet greywatch_psad in iif "lo" counter accept
add rule inet greywatch_psad in ct state established,related counter accept
add rule inet greywatch_psad in limit rate 12/minute burst 24 packets log level warn prefix "PSAD-IN: "
add rule inet greywatch_psad in counter accept
NFT
    note "created greywatch_psad inbound log chain (rate-limited 12/min)"
    CHANGED=1
fi

# 2. the whitelist comes FIRST, before any auto-block exists --------------
if [ ! -f "$PSAD_CONF" ]; then
    note "no psad config at $PSAD_CONF (is psad installed?)"; exit 66
fi
if grep -Eq '^ENABLE_AUTO_IDS[:[:space:]]+Y;' "$PSAD_CONF" 2>/dev/null; then
    note "psad auto-ids already armed"
else
    [ -f "$PSAD_CONF.greywatch-orig" ] || cp -n "$PSAD_CONF" \
        "$PSAD_CONF.greywatch-orig" 2>/dev/null
    # the [[:space:]] anchor stops each match at the variable's own name;
    # without it ENABLE_AUTO_IDS also eats ENABLE_AUTO_IDS_REGEX and
    # ENABLE_AUTO_IDS_EMAILS (the restart-dead config bug of 2026-11-06)
    sed -i 's|^ENABLE_AUTO_IDS[[:space:]].*;|ENABLE_AUTO_IDS             Y;|' "$PSAD_CONF" || true
    sed -i 's|^AUTO_IDS_DANGER_LEVEL[[:space:]].*;|AUTO_IDS_DANGER_LEVEL    5;|' "$PSAD_CONF" || true
    sed -i 's|^EMAIL_ALERT_DANGER_LEVEL[[:space:]].*;|EMAIL_ALERT_DANGER_LEVEL 2;|' "$PSAD_CONF" || true
    note "auto-ids armed: block only at danger level 5, alerts from level 2"
    CHANGED=1
fi
# whitelist: the LAN /24 and the gateway of the default route, derived from
# live system facts, never from a hardcoded home directory
GW="$("$IP_BIN" -4 route show default 2>/dev/null | awk '{print $3; exit}')"
L="$("$IP_BIN" -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | head -1)"
if [ -n "$L" ]; then
    NET24="${L%.*}.0/24"
    touch "$PSAD_WHITELIST" 2>/dev/null || { note "cannot write $PSAD_WHITELIST"; exit 66; }
    if grep -qF "$NET24" "$PSAD_WHITELIST"; then
        note "whitelist already carries $NET24"
    else
        printf '%s\n' "$NET24" >> "$PSAD_WHITELIST"
        note "whitelisted own LAN range $NET24"
        CHANGED=1
    fi
fi
# loopback is never a scanner: self-traffic must never score DL2 and
# flood the block ledger (the 2026-11-06 false-positive storm finding)
if grep -qF "127.0.0.0/8" "$PSAD_WHITELIST" 2>/dev/null; then
    note "whitelist already carries loopback"
else
    printf '127.0.0.0/8\n' >> "$PSAD_WHITELIST" 2>/dev/null
    note "whitelisted loopback 127.0.0.0/8 (self-traffic is not a scan)"
    CHANGED=1
fi
if [ -n "$GW" ] && grep -qF "$GW" "$PSAD_WHITELIST" 2>/dev/null; then
    note "whitelist already carries gateway $GW"
else
    [ -n "$GW" ] && { printf '%s\n' "$GW" >> "$PSAD_WHITELIST" 2>/dev/null;
                      note "whitelisted gateway $GW"; CHANGED=1; }
fi

# 3. ufw, only when it is the active frontend (it is not on this box) -----
U_LOG="$("$UFW_BIN" status verbose 2>/dev/null | awk '/^Logging:/ {print $3}' | tr -d '()')"
U_ON="$("$UFW_BIN" status 2>/dev/null | grep -c 'status: active')"
if [ "$U_ON" = "1" ] && [ "$U_LOG" != "medium" ]; then
    "$UFW_BIN" logging medium >/dev/null 2>&1 \
        && { note "ufw logging raised to medium"; CHANGED=1; } \
        || note "ufw logging raise failed (ufw active but unmanageable)"
fi

# 4. the kernel-log bridge: psad's reader drinks from the classic syslog
#    files; on a journald-only box (rsyslog installed but inactive) nothing
#    ever lands there and psad is BLIND no matter what else is perfect.
RS_STATE="$("$SYSTEMCTL_BIN" is-active rsyslog.service 2>/dev/null)"
if [ ! -e "$KERN_LOG" ] && [ -x /usr/sbin/rsyslogd ]; then
    "$SYSTEMCTL_BIN" unmask rsyslog.service >/dev/null 2>&1 || true
    "$SYSTEMCTL_BIN" enable --now rsyslog.service >/dev/null 2>&1 \
        && { note "rsyslog enabled: /var/log/kern.log will now fill (psad's reader is fed)"; CHANGED=1; } \
        || note "rsyslog enable failed; psad's kmsgsd stays starved"
elif [ ! -x /usr/sbin/rsyslogd ]; then
    note "rsyslog is not installed on this system; psad's kernel-log reader needs a syslog source"
    exit 3
fi

# 4b. aim psad's parser at a kernel log that EXISTS: Debian's shipped
#     default points at /var/log/messages, which modern systems never
#     write (rsyslog puts kernel lines in /var/log/kern.log), leaving
#     psad parsing silence forever (the 2026-11-06 deafness bug)
P_LOG="$(grep -E '^IPT_SYSLOG_FILE' "$PSAD_CONF" 2>/dev/null \
    | awk '{print $2}' | tr -d ';')"
if [ -e "$KERN_LOG" ] && [ "$P_LOG" != "$KERN_LOG" ]; then
    sed -i "s|^IPT_SYSLOG_FILE[[:space:]].*;|IPT_SYSLOG_FILE    $KERN_LOG;|" \
        "$PSAD_CONF" || true
    sed -i 's|^SYSLOG_DAEMON[[:space:]].*;|SYSLOG_DAEMON    rsyslog;|' \
        "$PSAD_CONF" || true
    note "psad now parses $KERN_LOG directly (was $P_LOG, rsyslog parser)"
    CHANGED=1
fi

# 5. restart psad so the new config is live, then prove it ---------------
if [ "$CHANGED" = "1" ]; then
    "$SYSTEMCTL_BIN" restart psad.service 2>/dev/null \
        && note "psad restarted with the new config" \
        || note "psad restart failed; apply it at the next reboot"
fi
ISACT="$("$SYSTEMCTL_BIN" is-active psad.service 2>/dev/null)"
NOTE_LOG=""
[ -e "$KERN_LOG" ] || NOTE_LOG="no kernel log readable at $KERN_LOG: psad's kmsgsd would be starved on this system"
if [ -n "$NOTE_LOG" ]; then
    note "$NOTE_LOG"
    exit 3
fi
[ "$ISACT" = "active" ] || { note "psad.service is $ISACT"; exit 4; }
note "done"
exit 0
