#!/bin/bash
systemctl restart greywatch.service
systemctl stop suricata.service
systemctl disable suricata.service 2>/dev/null
apt-get remove --purge -y suricata suricata-update 2>/dev/null
systemctl start greywatch-cve.timer
GW="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
systemctl is-active greywatch greywatch-cve.timer
echo "== engine check: the switch must exist and read disabled-by-default =="
cat "$GW/data/appfw/enable.json"
