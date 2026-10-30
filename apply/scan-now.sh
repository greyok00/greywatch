#!/bin/bash
set -uo pipefail
GW_DIR="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
GH="${GW_USER_HOME:-$(dirname "$GW_DIR")}"
[ $# -eq 1 ] || { echo "usage: scan-now.sh <yara|clamav|rkhunter|lynis|aide>" >&2; exit 64; }
case "$1" in
  yara)     # user unit: reach the user manager, not the system bus
            GW_USER_NAME="${GW_USER:-grey}"
            systemctl --user --machine="${GW_USER_NAME}@.host" start yara-tmp-scan.service 2>/dev/null \
              || runuser -u "$GW_USER_NAME" -- env \
                   XDG_RUNTIME_DIR="/run/user/$(id -u "$GW_USER_NAME")" \
                   systemctl --user start yara-tmp-scan.service 2>/dev/null
            exit $?;;
  clamav)   nohup /usr/bin/clamscan -r --infected \
              --log="$GH/security-hardening/clam-scan.log" \
              "$GH" /tmp /var/tmp >/dev/null 2>&1 & echo started clamav; exit 0;;
  aide)     exec systemctl start aide-check.service;;
  rkhunter) nohup /usr/bin/rkhunter --check --sk --report-warnings-only >> /var/log/rkhunter.log 2>&1 & echo started rkhunter; exit 0;;
  lynis)    nohup /usr/sbin/lynis audit system >> /var/log/lynis.log 2>&1 & echo started lynis; exit 0;;
  *) echo "unknown scan target" >&2; exit 65;;
esac
