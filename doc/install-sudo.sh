#!/bin/bash
# greywatch — the ONE sudo moment (run by the owner once; everything else
# needed no root). Review before running; nothing here is destructive.
# The repo copies of the units and the pkexec policy are TEMPLATES:
# __GW_HOME__ is resolved HERE, into the installed copies only, from the
# location this script was run from (the project must sit inside the
# user's home for the default layout to hold).
set -euo pipefail
DOC="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
GW="$(dirname "$DOC")"
GW_HOME="$(dirname "$GW")"
IFACE="$(awk 'NR>1 && $2=="00000000" {print $1; exit}' /proc/net/route)"
[ -n "$IFACE" ] || IFACE=none
[ -f "$DOC/greywatch.service" ] || { echo "run this from the project's doc/ directory" >&2; exit 66; }
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
resolve() { sed "s|__GW_HOME__|${GW_HOME}|g" "$DOC/$1" > "${TMP}/${1##*/}"; }
echo "== 0. resolved install home: ${GW_HOME} (iface: ${IFACE}) =="
echo "== 1. arpwatch on the default iface =="
systemctl enable --now "arpwatch@${IFACE}.service"
systemctl is-active "arpwatch@${IFACE}"
echo "== 2. greywatch root service =="
resolve greywatch.service
install -m 0644 "${TMP}/greywatch.service" /etc/systemd/system/greywatch.service
systemctl daemon-reload
systemctl enable --now greywatch.service
systemctl is-active greywatch
echo "== 3. pkexec policy (G3.7 allowlist) =="
resolve greywatch.apply.policy
install -m 0644 "${TMP}/greywatch.apply.policy" /usr/share/polkit-1/actions/greywatch.apply.policy
echo "== 4. cve-refresh weekly timer =="
if [ -f "$DOC/greywatch-cve.service" ]; then
  resolve greywatch-cve.service
  install -m 0644 "${TMP}/greywatch-cve.service" /etc/systemd/system/greywatch-cve.service
fi
install -m 0644 "$DOC/greywatch-cve.timer" /etc/systemd/system/ 2>/dev/null || \
  echo "(no prebuilt timer — create after review)"
systemctl daemon-reload
systemctl enable --now greywatch-cve.timer 2>/dev/null || true
echo "== DONE — run the remaining gate items from the plan (G2.4/G3.5/G3.6/G3.8/G4) as root via pkexec/sudo =="