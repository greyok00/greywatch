#!/bin/bash
# sync-to-system.sh - the ONE command that deploys today's greywatch to
# the installed tree and turns the real-clamd design on. Safe to re-run:
# every step is idempotent. Run it with sudo, from anywhere:
#   sudo bash ./sync-to-system.sh
set -euo pipefail
SRC="${GW_SRC:-$(cd "$(dirname "$(readlink -f "$0")")" && pwd)}"
LIB="${GW_LIB:-/usr/lib/greywatch}"
step() { echo "== $1"; }

[ -d "$SRC" ] && [ -d "$LIB" ] || {
    echo "FATAL: expected $SRC (checkout) and $LIB (installed tree)" >&2
    exit 1
}

step "syncing code"
# Every top-level module ships: the old hand-maintained list silently
# stopped at greywatch_daemon.py and stranded feeds/rules/parsers/
# decisions_factory/blockreviewer in the checkout, so installed code
# lagged behind the tree after every sync.
cp "$SRC"/*.py "$SRC"/install.sh "$SRC"/registry.json "$LIB"/
mkdir -p "$LIB"/appfw "$LIB"/assistant "$LIB"/wiz "$LIB"/schemas
cp "$SRC"/appfw/*.py "$SRC"/appfw/nfq_worker.c "$LIB"/appfw/
cp "$SRC"/assistant/*.py "$LIB"/assistant/
cp "$SRC"/wiz/*.py "$LIB"/wiz/
cp "$SRC"/schemas/*.py "$SRC"/schemas/*.json "$LIB"/schemas/
install -Dm 0755 "$SRC/tools/build_knowledge_index.py" \
    "$LIB/tools/build_knowledge_index.py"
# subdirectory files need their own cp: a flat cp DROPS the dirname and
# strands the file at the tree root (seen live 2026-11-14: the fixed
# plan_document never reached /usr/lib/greywatch/hardening/)
install -Dm 0644 "$SRC/hardening/apply.py" "$LIB/hardening/apply.py"
rm -f "$LIB/apply.py"     # remove the stray the flat copy made
cp "$SRC"/apply/harden.sh "$LIB"/apply/
mkdir -p "$LIB"/data
cp "$SRC"/data/baseline-configs.json "$LIB"/data/

step "syncing the core package (posture, netmon, the scan whitelist)"
# the core/ modules ship every time: posture and netmon landed after the
# last flat-cp wave and a stale core/ on the machine breaks the new verbs
mkdir -p "$LIB/core"
cp "$SRC"/core/*.py "$LIB"/core/
# the stranded cli.py/scan_session.py copies a flat cp left in core/
# (2026-11-14); nothing imports them, the real ones live at the root
rm -f "$LIB/core/cli.py" "$LIB/core/scan_session.py"

step "syncing the current UI and its assets"
# The installed shell must track the checkout. Before 2026-11-20 this
# script copied the daemon and CLI but never ui/, so /usr/lib/greywatch
# stayed on the retired v3 window.py shell while the dev tree moved on.
mkdir -p "$LIB/ui" "$LIB/assets"
cp "$SRC"/ui/*.py "$SRC"/ui/*.css "$SRC"/ui/*.sh "$LIB"/ui/
chmod 0755 "$LIB"/ui/*.sh
# Prune only stale top-level UI modules: never touch an unknown subdir.
for installed in "$LIB"/ui/*.py; do
    [ -f "$installed" ] || continue
    name="$(basename "$installed")"
    if [ ! -f "$SRC/ui/$name" ]; then
        echo "  removing retired UI module: ui/$name"
        rm -f "$installed"
    fi
done
cp -a "$SRC"/assets/. "$LIB"/assets/
# The system menu entry must point at a tree that exists. The old one
# carried /opt/greywatch/ui/app.py, and /opt/greywatch was never built.
SYSTEM_DESKTOP=/usr/share/applications/greywatch.desktop
cat > "$SYSTEM_DESKTOP" <<EOF
[Desktop Entry]
Type=Application
Name=greywatch
Comment=AI-enabled endpoint security for the Linux desktop
Exec=$LIB/ui/launch.sh
Icon=greywatch
Terminal=false
Categories=System;Security;Monitor;
EOF
chmod 0644 "$SYSTEM_DESKTOP"

step "syncing helpers"
# every helper, all at once: single-file lists stranded arpwrite.sh on
# an October copy that lacked the -a flag the verified config needs
cp "$SRC"/apply/*.sh "$LIB"/apply/
chmod 0755 "$LIB"/apply/clam-session.sh "$LIB"/apply/request-scan.sh
chmod 0755 "$LIB"/apply/scan-now.sh "$LIB"/apply/tool-control.sh
chmod 0755 "$LIB"/apply/netguard.sh "$LIB"/apply/netguard-block.sh

step "syncing tool digests"
mkdir -p "$LIB"/tool-digests
cp "$SRC"/tool-digests/*.md "$LIB"/tool-digests/
cp "$SRC"/doc/clamav-daemon-limits.conf "$SRC"/doc/freshclam-limits.conf "$LIB"/doc/

step "installing the corrected boot sweep"
install -Dm 0755 "$SRC/tools/greywatch-boot-sweep.sh" \
    /usr/local/sbin/greywatch-boot-sweep

step "installing the polkit policy (the read.posture action rides it)"
install -Dm 0644 "$SRC/apply/polkit/greywatch.apply.policy" \
    /usr/share/polkit-1/actions/greywatch.apply.policy
# The policy is a template: every action's exec.path carries __GW_LIB__.
sed -i "s#__GW_LIB__#$LIB#g" \
    /usr/share/polkit-1/actions/greywatch.apply.policy
# polkitd picks up the change from the directory; no restart needed.

step "installing the daily clam schedule units"
install -Dm 0644 "$SRC/doc/greywatch-clam-scan.service" /etc/systemd/system/
install -Dm 0644 "$SRC/doc/greywatch-clam-scan.timer" /etc/systemd/system/

step "installing the weekly CVE tracker unit"
sed "s#__GW_LIB__#$LIB#g" "$SRC/doc/greywatch-cve.service" \
    > /tmp/greywatch-cve.service
install -Dm 0644 /tmp/greywatch-cve.service \
    /etc/systemd/system/greywatch-cve.service
rm -f /tmp/greywatch-cve.service
install -Dm 0644 "$SRC/doc/greywatch-cve.timer" /etc/systemd/system/

step "removing the retired caps so the engine is never degraded"
rm -f /etc/systemd/system/clamav-daemon.service.d/limits.conf
rm -f /etc/systemd/system/freshclam.service.d/limits.conf
rmdir /etc/systemd/system/clamav-daemon.service.d 2>/dev/null || true
rmdir /etc/systemd/system/freshclam.service.d 2>/dev/null || true

step "clearing stale scan state (the deploy boundary starts a fresh run)"
rm -f /var/lib/greywatch/run-scan-state.json /var/lib/greywatch/data/run-scan-state.json 2>/dev/null || true

step "clearing stale stage dirs (each context recreates its own)"
rm -rf /var/lib/greywatch/.root-tmp /var/lib/greywatch/feeds/.root-tmp \
       /var/lib/greywatch/data/.root-tmp 2>/dev/null || true

step "rebuilding the knowledge index (docs + linux commands + guides)"
# the knowledge extras are CURATED (owner 2026-11-14): only the corpora
# that carry the app's docs-and-linux-commands contract enter the
# library; everything else in the research lane stays research
KNOWN_CORPORA=(
    "guides-2026-11-14"
)
GUIDES_ROOT="${GW_GUIDES_ROOT:-}"
mkdir -p /var/lib/greywatch/knowledge/extra
for name in "${KNOWN_CORPORA[@]}"; do
    [ -n "$GUIDES_ROOT" ] || continue
    src="$GUIDES_ROOT/$name"
    if [ -d "$src" ]; then
        mkdir -p "/var/lib/greywatch/knowledge/extra/$name"
        cp -ru -- "$src"*.md "/var/lib/greywatch/knowledge/extra/$name/" 2>/dev/null || true
    fi
done
# and anything the earlier broad copy planted that is not curated goes
# back out of the library
find /var/lib/greywatch/knowledge/extra -mindepth 1 -maxdepth 1 \
    -type d ! -name "guides-2026-11-14" -exec rm -rf {} + 2>/dev/null || true
python3 "$LIB/tools/build_knowledge_index.py" \
    || echo "WARN: knowledge index rebuild failed (the old index stands)"
chmod 0640 /var/lib/greywatch/knowledge-index.json 2>/dev/null || true
chgrp grey /var/lib/greywatch/knowledge-index.json 2>/dev/null || true

step "teaching the resident engine the scratch paths it never scans"
CLAMD_CONF=/etc/clamav/clamd.conf
if [ -f "$CLAMD_CONF" ]; then
    if ! grep -q "GW-POLICY-EXCLUDES" "$CLAMD_CONF"; then
        printf '\n# GW-POLICY-EXCLUDES (greywatch, 2026-11-14): the\n' \
            >> "$CLAMD_CONF"
        printf '# scan scratch trees are app-owned, never findings\n' \
            >> "$CLAMD_CONF"
        printf 'ExcludePath /tmp/pytest-of-grey\n' >> "$CLAMD_CONF"
        printf 'ExcludePath /tmp/pytest-tmp\n' >> "$CLAMD_CONF"
        printf 'ExcludePath /tmp/gw-eicar\n' >> "$CLAMD_CONF"
        printf 'ExcludePath /tmp/gw-live\n' >> "$CLAMD_CONF"
        printf 'ExcludePath /etc/unicornscan\n' >> "$CLAMD_CONF"
    fi
    systemctl try-restart clamav-daemon.service 2>/dev/null || true
fi

step "teaching the resolver to keep a query log (the DNS monitor's feed)"
DNSCONF=/etc/dnsmasq.conf
if [ -f "$DNSCONF" ]; then
    if ! grep -q "GW-DNSLOG" "$DNSCONF"; then
        printf '\n# GW-DNSLOG (greywatch, 2026-11-15): the DNS monitor\n' \
            >> "$DNSCONF"
        printf '# store derives from this query log; slow lane only\n' \
            >> "$DNSCONF"
        printf 'log-queries\n' >> "$DNSCONF"
    fi
    systemctl try-restart dnsmasq.service 2>/dev/null || true
fi

step "reloading systemd and turning everything on"
systemctl daemon-reload
# The resident engine is retired (owner 2026-11-17: the uncapped clamd
# sat at CPUQuota=infinity and made real work impossible). The
# antivirus answer is the one-shot lane only: its timer carries the
# schedule, the definitions keep updating, and the daemon is masked so
# nothing ever starts it again - not this sync, not the boot, nothing.
systemctl stop clamav-daemon.service clamav-daemon.socket 2>/dev/null || true
systemctl disable clamav-daemon.service clamav-daemon.socket 2>/dev/null || true
systemctl mask clamav-daemon.service clamav-daemon.socket
systemctl enable --now clamav-freshclam.service
systemctl disable --now greywatch-clam-scan.timer 2>/dev/null || true
systemctl disable --now greywatch-boot-sweep.timer 2>/dev/null || true
systemctl enable --now greywatch-cve.timer
systemctl reset-failed greywatch-cve.service 2>/dev/null || true
systemctl restart greywatch.service

step "self-verification"
# `systemctl is-enabled` and `grep -c` return nonzero for the *correct*
# state here (masked/disabled/no match). They are reports, not gates;
# without `|| true`, set -e aborted the sync after a successful deploy.
echo -n "clamd masked (want masked): "; systemctl is-enabled clamav-daemon.service || true
echo -n "daily timer (want disabled): "; systemctl is-enabled greywatch-clam-scan.timer || true
echo -n "boot sweep (want disabled): "; systemctl is-enabled greywatch-boot-sweep.timer || true
echo -n "scanners throttle on:      "; grep -c "\"max-speed\": (SCAN_ALL, True)" "$LIB/scan_session.py" || true
echo -n "session script on system: "; [ -f "$LIB/apply/clam-session.sh" ] \
    && echo present || echo MISSING
echo -n "schedule timer:          "; systemctl is-enabled \
    greywatch-clam-scan.timer || true
echo -n "baseline configs on system: "; [ -f "$LIB/data/baseline-configs.json" ] \
    && echo present || echo MISSING
echo -n "unit-arm verb on system:    "; grep -c "unit-arm)" "$LIB/apply/harden.sh" || true
echo -n "current UI on system:       "; [ -f "$LIB/ui/security.py" ] \
    && [ -f "$LIB/ui/tools.py" ] && [ -f "$LIB/ui/launch.sh" ] \
    && echo present || echo MISSING
echo -n "system launcher target:     "; grep -q "Exec=$LIB/ui/launch.sh" \
    /usr/share/applications/greywatch.desktop && echo current || echo STALE
echo "SYNC-COMPLETE"
