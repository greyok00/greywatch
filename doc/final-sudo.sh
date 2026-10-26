#!/bin/bash
# greywatch — final sudo step (review first!):
# 1. restart the service (noise gate, heartbeats, headless appfw engine, 17-tool roster)
systemctl restart greywatch.service
# 2. suricata: owner-approved removal (dropped for the lighter in-daemon net-watch)
systemctl stop suricata.service
systemctl disable suricata.service 2>/dev/null
apt-get remove --purge -y suricata suricata-update 2>/dev/null
# 3. start the CVE weekly timer
systemctl start greywatch-cve.timer
GW="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
systemctl is-active greywatch greywatch-cve.timer
echo "== engine check: the switch must exist and read disabled-by-default =="
cat "$GW/data/appfw/enable.json"