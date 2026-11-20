#!/bin/bash
set -uo pipefail
GW_DIR="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
GH="${GW_USER_HOME:-$(dirname "$GW_DIR")}"
STATE_FILE="$GW_DIR/data/run-scan-state.json"

usage64() {
    echo "usage: scan-now.sh <yara|clamav|rkhunter|lynis|aide>" \
         "| start-all | digest <rkhunter> [lynis ...]" >&2
    exit 64
}

# single-tool launches: the daemon and every existing caller rely on
# these exact commands and exit codes, so the bodies stay byte-identical
# to the pre-2026-11-14 branches (only wrapped in a function).
scan_one() {
    # One scan at a time. This helper no longer launches a scanner: it
    # files the request and the resident service starts it, in order,
    # behind the one global lock.
    local key
    case "$1" in
      yara) key="yara-tmp-scan" ;;
      clamav|rkhunter|lynis|aide) key="$1" ;;
      *) echo "unknown scan target" >&2; return 65 ;;
    esac
    bash "$(dirname "$(readlink -f "$0")")/request-scan.sh" "$key"
}

# start-all: launch every detector in one helper pass (one prompt instead
# of five) so the CLI can wait and then print results instead of only
# "started" notes (owner 2026-11-14: the CLI is the product and run must
# show results). Records how far the root-held rkhunter log had grown
# BEFORE launching, so digest hands back only this run's warnings.
start_all() {
    local ui_user="${GW_USER:-grey}" ui_home
    ui_home=$(getent passwd "$ui_user" 2>/dev/null | cut -d: -f6)
    [ -n "$ui_home" ] || ui_home="$GH"
    # clamav and the yara result files belong in the user's tree, where
    # the daemon and the CLI both look; the bare dirname fallback was
    # /usr/lib when the installed copy ran.
    export GW_USER_HOME="$ui_home"
    GH="$ui_home"
    local rc=0
    mkdir -p "$GW_DIR/data" || { echo "STATE-DIR-FAILED $GW_DIR/data" >&2; return 2; }
    local rkh_off=0
    if [ -f /var/log/rkhunter.log ]; then
        rkh_off=$(stat -c %s /var/log/rkhunter.log 2>/dev/null || echo 0)
    fi
    local epoch started_iso
    epoch=$(date +%s)
    started_iso=$(date -Is)

    # One request, one session, every scanner in order. The daemon
    # sequences them; this helper never starts a scanner of its own, so a
    # timer, a button and a terminal cannot produce a second run.
    if ! bash "$(dirname "$(readlink -f "$0")")/request-scan.sh" full; then
        echo "start-failed full"
        rc=1
    fi

    local yara_off=0 clam_off=0
    [ -f "$ui_home/security-hardening/yara-scan.log" ] && \
        yara_off=$(stat -c %s "$ui_home/security-hardening/yara-scan.log" \
                   2>/dev/null || echo 0)
    [ -f "$ui_home/security-hardening/clam-scan.log" ] && \
        clam_off=$(stat -c %s "$ui_home/security-hardening/clam-scan.log" \
                   2>/dev/null || echo 0)

    python3 - "$STATE_FILE" "$started_iso" "$epoch" "$rkh_off" \
              "$yara_off" "$clam_off" \
              "$ui_home/security-hardening/yara-scan.log" \
              "$ui_home/security-hardening/clam-scan.log" \
              "$ui_home/security-reports/aide/last-check.txt" <<'PY'
import json, os, sys
path, iso, epoch, roff, yoff, coff, yara_log, clam_log, aide_report = \
    sys.argv[1:10]
doc = {"started": iso, "epoch": float(epoch),
       "rkhunter_offset": int(roff), "yara_offset": int(yoff),
       "clam_offset": int(coff),
       "yara_log": yara_log, "clam_log": clam_log, "aide_report": aide_report}
tmp = path + ".tmp"
with open(tmp, "w", encoding="utf-8") as fh:
    fh.write(json.dumps(doc) + "\n")
os.replace(tmp, path)
PY
    local write_rc=$?
    [ "$write_rc" -eq 0 ] || { echo "STATE-WRITE-FAILED $STATE_FILE"; rc=1; }
    chmod 0644 "$STATE_FILE" 2>/dev/null
    echo "STATE $STATE_FILE"
    return "$rc"
}

# digest: print the root-held results (rkhunter, lynis) as plain text
# the CLI parses client-side. Only this run's section is printed for
# rkhunter, via the offset start-all recorded. A missing or unreadable
# state file is an honest failure, not an empty digest.
digest() {
    [ $# -ge 1 ] || usage64
    if [ ! -r "$STATE_FILE" ]; then
        echo "NO-STATE $STATE_FILE" >&2
        exit 67
    fi
    local t off
    for t in "$@"; do
        case "$t" in
          rkhunter)
              off=$(python3 -c 'import json,sys
try:
    print(json.load(open(sys.argv[1], encoding="utf-8"))["rkhunter_offset"])
except (OSError, ValueError, KeyError):
    sys.exit(2)' "$STATE_FILE") || { echo "NO-STATE $STATE_FILE" >&2; exit 67; }
              echo "# TOOL rkhunter"
              if [ -f /var/log/rkhunter.log ]; then
                  tail -c "+$((off + 1))" /var/log/rkhunter.log | head -n 200
              else
                  echo "REPORT-UNAVAILABLE /var/log/rkhunter.log"
              fi
              ;;
          lynis)
              echo "# TOOL lynis"
              if [ -f /var/log/lynis-report.dat ]; then
                  grep '^hardening_index=' /var/log/lynis-report.dat | head -n 1
                  grep '^warning\[\]=' /var/log/lynis-report.dat | head -n 20
              else
                  echo "REPORT-UNAVAILABLE /var/log/lynis-report.dat"
              fi
              ;;
          *)
              echo "unknown digest target: $t" >&2
              exit 65
              ;;
        esac
    done
}

case "$1" in
    start-all) [ $# -eq 1 ] || usage64; start_all; exit $?;;
    digest)    shift; digest "$@"; exit $?;;
esac

[ $# -eq 1 ] || usage64
scan_one "$1"
exit $?
