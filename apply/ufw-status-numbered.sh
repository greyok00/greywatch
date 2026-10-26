#!/bin/bash
# helper (pkexec only): numbered status for verify (read-only)
set -euo pipefail
exec /usr/sbin/ufw status numbered
