#!/bin/bash
set -euo pipefail
GW_DIR="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
[ $# -ge 2 ] || { echo "usage: ufw-apply.sh ACTION DIRECTION [...]" >&2; exit 64; }
case "$1" in allow|deny|reject|limit) ;; *) echo "bad action: $1" >&2; exit 65;; esac
case "$2" in in|out) ;; *) echo "bad direction: $2" >&2; exit 65;; esac
ACTION="$1"; DIRECTION="$2"; shift 2
PORT="" PROTO="" FROM="" COMMENT=""
while [ $# -gt 0 ]; do
  case "$1" in
    from) [ $# -ge 2 ] || { echo "from needs an IP" >&2; exit 65; }
          [[ $2 =~ ^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])([.](25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}$ ]] || { echo "bad from IP: $2" >&2; exit 65; }
          FROM="$2"; shift 2 ;;
    to)    [[ "$2" =~ ^any$ ]] || { echo "only 'to any' supported" >&2; exit 65; }; shift 2 ;;
    port)  [[ "$2" =~ ^[0-9]{1,5}$ ]] || { echo "bad port: $2" >&2; exit 65; }
           [ "$2" -ge 1 ] && [ "$2" -le 65535 ] || { echo "port range" >&2; exit 65; }
           PORT="$2"; shift 2 ;;
    proto) [[ "$3" =~ ^(tcp|udp|icmp)$ ]] || { echo "bad proto" >&2; exit 65; }
           PROTO="$3"; shift 2 ;;
    comment) [[ "$2" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || { echo "bad comment" >&2; exit 65; }
           COMMENT="$2"; shift 2 ;;
    *) echo "unvalidated token: $1" >&2; exit 65 ;;
  esac
done
if [ -z "$PORT" ] && [ -n "$PROTO" ]; then echo "proto without port" >&2; exit 65; fi
if [ -n "$PROTO" ] && [ -z "$PORT" ]; then echo "proto without port" >&2; exit 65; fi
if [ -n "$PORT" ] && [ -z "$PROTO" ]; then echo "port without proto" >&2; exit 65; fi
CMD=(/usr/sbin/ufw "$ACTION" "$DIRECTION")
[ -n "$FROM" ] && CMD+=(from "$FROM")
[ -n "$PORT" ] && CMD+=(to any port "$PORT" proto "$PROTO")
[ -n "$COMMENT" ] && CMD+=(comment "$COMMENT")
printf '%s\n' "$(date -Is) ufw-apply ${CMD[*]}" >> "$GW_DIR/data/helper-actions.log"
exec "${CMD[@]}"
