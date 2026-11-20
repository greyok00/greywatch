#!/bin/bash
# Run a few minutes after boot, once the machine has settled.
set -uo pipefail
GH="$(getent passwd "${GW_USER:-grey}" 2>/dev/null | cut -d: -f6)"
[ -n "$GH" ] || GH="/home/${GW_USER:-grey}"
LOGDIR="$GH/security-hardening"
mkdir -p "$LOGDIR"
IFACE="$(ip -br link | awk '$2=="UP" && $1!="lo" {print $1; exit}')"

# every service should already be up; nudge anything that is not.
# The resident ClamAV engine is retired and masked - never mentioned here.
for u in clamav-freshclam.service fail2ban.service \
         ufw.service auditd.service apparmor.service responderd.service \
         tetragon.service greywatch.service; do
  systemctl start "$u" 2>/dev/null || true
done
[ -n "$IFACE" ] && systemctl start "arpwatch@$IFACE.service" 2>/dev/null || true

# No automatic scan at boot. The daily timer is disabled and the boot
# sweep does not start a run of its own; scans start from the desk or CLI.


echo "$(date -Is) boot sweep finished" >> "$LOGDIR/boot-sweep.log"
chown "${GW_USER:-grey}:" "$LOGDIR/boot-sweep.log" 2>/dev/null || true
