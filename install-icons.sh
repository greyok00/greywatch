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

# Per-tool icons: uniform 24x24 stroke symbols, installed as *-symbolic so
# GTK tints them with the theme's ink colour instead of shipping emoji.
TOOLS="$GW/assets/icons/tools"
mkdir -p "$ICONS/scalable/apps"
cp "$TOOLS"/gw-tool-*-symbolic.svg "$ICONS/scalable/apps/"

mkdir -p "$APPS"
cat > "$APPS/greywatch.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=greywatch
Comment=AI-enabled endpoint security for the Linux desktop
Exec=python3 $GW/ui/app.py
Icon=greywatch
Terminal=false
Categories=System;Security;Monitor;
EOF

if command -v gtk-update-icon-cache >/dev/null; then
    gtk-update-icon-cache -qf "$ICONS" 2>/dev/null || true
fi
DESKTOP="$(xdg-user-dir DESKTOP 2>/dev/null || echo "$HOME/Desktop")"
mkdir -p "$DESKTOP"
cp "$APPS/greywatch.desktop" "$DESKTOP/greywatch.desktop"
chmod +x "$APPS/greywatch.desktop" "$DESKTOP/greywatch.desktop"
if command -v gio >/dev/null; then
    gio set "$DESKTOP/greywatch.desktop" metadata::trusted true 2>/dev/null || true
fi
# Desktop-session autostart. The daemon is a systemd service and starts at
# boot on its own; the GUI is a per-user app, so without this entry the
# dashboard only ever appears when someone clicks the icon.
AUTOSTART="${XDG_CONFIG_HOME:-$HOME/.config}/autostart"
mkdir -p "$AUTOSTART"
cat > "$AUTOSTART/greywatch.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=greywatch
Comment=AI-enabled endpoint security (daemon runs as a system service)
Exec=python3 $GW/ui/app.py
Icon=greywatch
Terminal=false
X-GNOME-Autostart-enabled=true
X-GNOME-Autostart-Delay=4
EOF

# Exactly one autostart entry. An older greywatch-tray.desktop launched the
# same app from an older path; two entries raced at login (the single-instance
# lock turns the loser into a no-op, but the duplicate is still noise).
if [ -f "$AUTOSTART/greywatch-tray.desktop" ] \
   && grep -q "ui/app.py" "$AUTOSTART/greywatch-tray.desktop"; then
    rm -f "$AUTOSTART/greywatch-tray.desktop"
    echo "removed duplicate autostart: $AUTOSTART/greywatch-tray.desktop"
fi

echo "installed: $ICONS/{16..256}/apps/greywatch.png"
echo "installed: $APPS/greywatch.desktop (Exec -> $GW/ui/app.py)"
echo "installed: $DESKTOP/greywatch.desktop (launches the dashboard)"
echo "installed: $AUTOSTART/greywatch.desktop (starts the dashboard at login)"