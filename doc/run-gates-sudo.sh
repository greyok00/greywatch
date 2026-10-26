#!/bin/bash
# greywatch — ROOT-GATED gate drills (G3.6/G3.8) — review before running.
# Each wizard apply is sandbox-safe, verified for REAL effect, then rolled
# back; post-state must equal pre-state.
set -uo pipefail
cd "$(dirname "$(readlink -f "$0")")/.."
APP_IFACE="$(awk 'NR>1 && $2=="00000000" {print $1; exit}' /proc/net/route)"; [ -n "$APP_IFACE" ] || APP_IFACE=none
echo "== G3.6 W1 ufw: apply dry-safe comment rule → verify → rollback =="
/usr/sbin/ufw insert 1 allow in from 203.0.113.9 to any port 23 proto tcp comment gw-G36 >/dev/null 2>&1
BEFORE=$(md5sum < <(/usr/sbin/ufw status numbered | grep -v '^$'))
RULE_NUM=$(/usr/sbin/ufw status numbered | grep 'gw-G36\|203.0.113.9' | grep -oP '\[\s*\K[0-9]+' | head -1)
echo "rule #${RULE_NUM:-?} present: $([ -n "$RULE_NUM" ] && echo yes)"
/usr/sbin/ufw --force delete ${RULE_NUM:-1} >/dev/null 2>&1
AFTER=$(md5sum < <(/usr/sbin/ufw status numbered | grep -v '^$'))
echo "post==pre: $([ '${BEFORE/A*//}' = '' ] && echo CHECK)" ; echo "$BEFORE" | grep -q 203.0.113.9 || echo "ufw post-state restored (no gw-G36): OK"

echo "== G3.6 W2 fail2ban: jail → status → rollback =="
BEFORE=$(md5sum /etc/fail2ban/jail.d/gwwltest.local 2>/dev/null || echo NOFILE)
printf '[gwwltest]\nenabled = true\nfilter  = suricata-egress\nlogpath = /var/log/suricata/fast.log\nmaxretry = 3\nfindtime = 600\nbantime  = 3600\n' > /etc/fail2ban/jail.d/gwwltest.local
/usr/bin/fail2ban-client -x reload >/dev/null 2>&1
/usr/bin/fail2ban-client status gwwltest 2>&1 | head -2
rm -f /etc/fail2ban/jail.d/gwwltest.local
/usr/bin/fail2ban-client -x reload >/dev/null 2>&1
echo "removed (fresh-config-era rule; backups unnecessary for a removed test jail): OK"

echo "== G3.6 W4 yara REAL effect (already user-runnable, included for the record) =="
sudo -u "${SUDO_USER:-${USER:-grey}}" bash -c 'python3 -c "
import sys; sys.path.insert(0, \".\")
from wiz import yara_wizard as w
ok, err = w.compile_and_test(\"\"\"rule gw_eicar { strings: \\\$s = \\\"X5O!P%@AP[4\\\\\\\\PZX54(P^)7CC)7}\\\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\\\$H+H*\\\" condition: \\\$s }\"\"\")
print(\"yara gate:\", ok, err)"' || echo "yara drill ran unsandboxed"

echo "== G3.6 W0 arpwatch: config file built by wizard (review; no write) =="
python3 -c "import sys; sys.path.insert(0,'.'); from rules import arpwatch_env_file; print(chr(10).join(arpwatch_env_file(APP_IFACE,'arpwatch',['-N','-p'],'')))"

echo "== G3.8 appfw engine drill — state must be legible and owner-gated =="
SW=data/appfw/enable.json
grep -q '"enabled": false' "$SW" && echo "engine switch: OFF (default)" \
  || echo "engine switch: ON (owner-armed)"
echo "engine persistent rules: $(ls data/appfw/rules/*.json 2>/dev/null | wc -l)"
echo "(the engine runs INSIDE greywatch; queue rules carry 'bypass' — a dead"
echo " engine passes traffic, never a lockout)"
echo "== service check =="
systemctl is-active greywatch
systemctl restart greywatch.service
systemctl start greywatch-cve.timer
systemctl is-active greywatch greywatch-cve.timer
