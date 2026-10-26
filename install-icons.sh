#!/bin/bash
# install-icons.sh — put the greywatch app icon and launcher into the
# user's freedesktop dirs (hicolor + ~/.local/share/applications), so the
# taskbar, alt-tab, and the app grid all show the wolf. No root needed;
# the GTK window resolves the icon by the name "greywatch" once installed.
# Idempotent — safe to re-run after pulling new icon sizes.
set -euo pipefail
GW="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
SRC="$GW/assets/logo"
DATA="${XDG_DATA_HOME:-$HOME/.local/share}"
ICONS="$DATA/icons/hicolor"
APPS="$DATA/applications"

for s in 16 24 32 48 64 128 256; do
    d="$ICONS/${s}x${s}/apps"
    mkdir -p "$d"
    cp "$SRC/greywatch-icon-$s.png" "$d/greywatch.png"
done
rm -f "$ICONS/128x128/actions/greywatch.png"

cat > "$APPS/greywatch.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=greywatch
Comment=One dashboard for every protection on this Linux machine
Exec=python3 $GW/ui/app.py
Icon=greywatch
Terminal=false
Categories=System;Security;Monitor;
EOF

if command -v gtk-update-icon-cache >/dev/null; then
    gtk-update-icon-cache -qf "$ICONS" 2>/dev/null || true
fi
echo "installed: $ICONS/{16..256}/apps/greywatch.png"
echo "installed: $APPS/greywatch.desktop (Exec -> $GW/ui/app.py)"