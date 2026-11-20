#!/bin/bash
# clam-session.sh — the daily timer's entry point.
#
# It files one antivirus request and exits. The resident service owns the
# scan slot, so the daily timer can never run beside an existing scan, and
# a service that is down leaves the request waiting instead of launching an
# unowned scanner.
set -u
KEY="${1:-clamav}"
exec bash "$(dirname "$(readlink -f "$0")")/request-scan.sh" "$KEY"
