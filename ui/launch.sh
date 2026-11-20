#!/bin/bash
# The one way into the GUI, whichever tree holds it (owner 2026-11-16).
# The desktop shortcut, the menu entry and the autostart entry all call
# this one script, so the links can never disagree about what they open:
# the dev tree first, then the deb's install tree.
#
# Plain launch (desktop or menu link): opens right away.
# --autostart: the login timer. GW_UI_AUTOSTART_DELAY (default 90 s) is
# the head start the rest of the session gets - the big model, the scan
# ramp, the tray stack load first and the dashboard opens into a settled
# desktop instead of into the boot flood. The number is a tunable: set
# the env var and it is your number.
set -euo pipefail

if [ "${1:-}" = "--autostart" ]; then
    shift
    sleep "${GW_UI_AUTOSTART_DELAY:-90}"
fi

for tree in "$HOME/greywatch" /usr/lib/greywatch /opt/greywatch; do
    if [ -f "$tree/ui/app.py" ]; then
        if [ "${1:-}" = "--resolve" ]; then
            # A diagnostic, not a launch: print which tree a link would
            # open and why, then stop.
            echo "launch: would open $tree/ui/app.py"
            exit 0
        fi
        exec python3 "$tree/ui/app.py" "$@"
    fi
done
echo "greywatch: no ui/app.py in any known tree" >&2
exit 64
