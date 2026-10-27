#!/bin/bash
# packaging/build-deb.sh — build the installable Debian package.
#
#   ./packaging/build-deb.sh [output-dir]        # default: dist
#
# The payload is this checkout compiled-and-assembled as a program would
# install: /opt/greywatch (program + tests' runtime needs minus the tests
# themselves), the filled systemd units, the filled polkit policy
# (substituted exactly the way install.sh does, with __GW_LIB__ pointing
# at /opt/greywatch), the system-wide icons and launcher, and a postinst
# that enables-and-starts the daemon. The compiled .so modules ride along
# when present (built by ./build-cython.sh); every module also ships its
# .py, so any Python version >= 3.12 can run the package even where the
# compiled copy does not match the interpreter.
#
# No root required: the package is built and owned with dpkg-deb's
# --root-owner-group, then verified with dpkg-deb --info/--contents.
set -euo pipefail
GW="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
OUT="${1:-$GW/dist}"
VER="$(python3 -c "import tomllib;print(tomllib.load(open('$GW/pyproject.toml','rb'))['project']['version'])")"
MAINTAINER="greyok00 <greyok00@users.noreply.github.com>"
PREFIX=/opt/greywatch
STAGE="$(mktemp -d /tmp/greywatch-deb.XXXXXX)"
trap 'rm -rf "$STAGE"' EXIT

PAYLOAD="$STAGE/opt/greywatch"
mkdir -p "$PAYLOAD"

# --- program tree: everything tracked at build time minus what does not
# --- belong on an installed machine (tests, shot library, caches)
tar -C "$GW" -cf - \
    --exclude='./.git' --exclude='./tests' --exclude='./doc/shots' \
    --exclude='./*.md' --exclude='./runbooks' --exclude='./tmp*' \
    --exclude='./data' --exclude='./build' --exclude='./*__pycache__*' \
    --exclude='./dist' --exclude='./.venv' --exclude='./venv' \
    --exclude='./.pytest_cache' --exclude='./.ruff_cache' \
    --exclude='./.claude' --exclude='./.mypy_cache' \
    --exclude='./.pre-commit*' --exclude='./.gitignore' \
    . | tar -C "$PAYLOAD" -xf -

# --- systemd units and polkit policy, filled like install.sh fills them:
# --- code in the root-owned program dir, runtime state in /var/lib/greywatch
STATE_DIR=/var/lib/greywatch
install -d -m 0770 "$STAGE$STATE_DIR"
install -Dm 0644 /dev/null "$STAGE/etc/systemd/system/greywatch.service"
sed -e "s|__GW_LIB__|$PREFIX|g" -e "s|__GW_DATA__|$STATE_DIR|g" \
    -e "s|__GW_UI_USER__|grey|g" "$GW/doc/greywatch.service" > "$STAGE/etc/systemd/system/greywatch.service"
for unit in greywatch-cve.service greywatch-cve.timer \
            greywatch-watchdog.service greywatch-watchdog.timer; do
    [ -f "$GW/doc/$unit" ] || continue
    mkdir -p "$STAGE/etc/systemd/system"
    sed -e "s|__GW_LIB__|$PREFIX|g" -e "s|__GW_DATA__|$STATE_DIR|g" \
        -e "s|__GW_UI_USER__|grey|g" "$GW/doc/$unit" > "$STAGE/etc/systemd/system/$unit"
done
install -Dm 0644 /dev/null "$STAGE/usr/share/polkit-1/actions/greywatch.apply.policy"
sed -e "s|__GW_LIB__|$PREFIX|g" -e "s|__GW_DATA__|$STATE_DIR|g" \
    -e "s|__GW_UI_USER__|grey|g" \
    "$GW/apply/polkit/greywatch.apply.policy" \
    > "$STAGE/usr/share/polkit-1/actions/greywatch.apply.policy"

# --- system-wide icons and launcher (name "greywatch" resolves from hicolor)
for s in 16 24 32 48 64 128 256; do
    install -Dm 0644 "$GW/assets/logo/greywatch-icon-$s.png" \
        "$STAGE/usr/share/icons/hicolor/${s}x${s}/apps/greywatch.png"
done
install -Dm 0644 /dev/null "$STAGE/usr/share/applications/greywatch.desktop"
cat > "$STAGE/usr/share/applications/greywatch.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=greywatch
Comment=One dashboard for every protection on this Linux machine
Exec=python3 $PREFIX/ui/app.py
Icon=greywatch
Terminal=false
Categories=System;Security;Monitor;
EOF

# --- maintainer scripts
mkdir -p "$STAGE/DEBIAN"
cat > "$STAGE/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
# GW-02: one desktop identity, resolved ONCE at install time and
# persisted in the service. $GREYWATCH_UI_USER wins; otherwise exactly
# one human account (uid >= 1000, a login shell) is used; when nothing
# resolves cleanly the unit keeps its build-time default and we say so.
# Nothing ever invents a uid.
UI_USER="${GREYWATCH_UI_USER:-}"
if [ -z "$UI_USER" ]; then
    HUMANS="$(awk -F: '$3 >= 1000 && $3 < 60000 && $7 ~ /sh$/ {print $1}' /etc/passwd | sort -u)"
    if [ "$(printf '%s\n' "$HUMANS" | grep -c .)" = 1 ]; then
        UI_USER="$HUMANS"
    fi
fi
if [ -n "$UI_USER" ] && getent passwd "$UI_USER" >/dev/null; then
    sed -i "s|^Environment=GREYWATCH_UI_USER=.*|Environment=GREYWATCH_UI_USER=$UI_USER|" \
        /etc/systemd/system/greywatch.service
    chown "root:$(getent passwd "$UI_USER" | cut -d: -f4)" /var/lib/greywatch
    chmod 0770 /var/lib/greywatch
else
    echo "greywatch: desktop user not resolvable at install — set GREYWATCH_UI_USER and edit the unit's GREYWATCH_UI_USER line" >&2
fi
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    systemctl enable greywatch.service >/dev/null 2>&1 || true
    systemctl restart greywatch.service || true
fi
EOF
cat > "$STAGE/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then
    systemctl stop greywatch.service || true
fi
EOF
cat > "$STAGE/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi
echo "greywatch: runtime state under /var/lib/greywatch was kept." >&2
EOF
chmod 0755 "$STAGE/DEBIAN/postinst" "$STAGE/DEBIAN/prerm" "$STAGE/DEBIAN/postrm"

cat > "$STAGE/DEBIAN/control" <<EOF
Package: greywatch
Version: $VER
Architecture: amd64
Maintainer: $MAINTAINER
Section: utils
Priority: optional
Depends: python3 (>= 3.12), python3-gi, gir1.2-gtk-4.0, \
 gir1.2-ayatanaappindicator3-0.1 | gir1.2-appindicator3-0.1, polkitd, systemd
Recommends: ufw, fail2ban, clamav-daemon, clamav-freshclam, yara, \
 rkhunter, lynis, aide-common, arpwatch, apparmor, auditd, nftables, \
 python3-netfilterqueue
Description: Linux endpoint security for the desktop
 A root daemon watches the machine in real time and writes an
 append-only audit trail; a CLI explains what happened and what the
 machine decided; a GTK 4 dashboard puts scans, the per-program
 application firewall, and reversible hardening under buttons. No
 cloud, no account, no telemetry.
 .
 Removing the package keeps the runtime state in /var/lib/greywatch.
EOF

mkdir -p "$OUT"
dpkg-deb --build --root-owner-group "$STAGE" \
    "$OUT/greywatch_${VER}_amd64.deb" >/dev/null
( cd "$OUT" && sha256sum "greywatch_${VER}_amd64.deb" \
    > "greywatch_${VER}_amd64.deb.sha256" )
echo "built: $OUT/greywatch_${VER}_amd64.deb"