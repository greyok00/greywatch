#!/bin/bash
# helper (pkexec only): rollback one ufw rule by its numbered status
set -euo pipefail
[ $# -eq 1 ] || { echo "usage: ufw-rollback.sh NUM" >&2; exit 64; }
[[ "$1" =~ ^[0-9]{1,4}$ ]] || { echo "bad rule number" >&2; exit 65; }
exec /usr/sbin/ufw --force delete "$1"
