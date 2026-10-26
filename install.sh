#!/bin/bash
# install.sh — deploy greywatch's system integration: the hardened
# systemd unit and the polkit allowlist, both with the __GW_HOME__
# placeholder substituted to this checkout's real path. Modes:
#
#   sudo ./install.sh               system files + restart, then user icons
#   sudo ./install.sh --no-restart  deploy files, leave the daemon running
#   sudo ./install.sh --uninstall   remove unit + policy (+ launcher); keeps data/
#   ./install.sh                    user icons + launcher only (no root)
#   ./install.sh --root DIR         install into a staging dir (self-test only)
#   ./install.sh --check [DIR]      verify a deployment (default: the real system)
#
# Templates: doc/greywatch.service and apply/polkit/greywatch.apply.policy.
set -euo pipefail
GW="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
UNIT_TPL="$GW/doc/greywatch.service"
POLICY_TPL="$GW/apply/polkit/greywatch.apply.policy"
UNIT_REL="etc/systemd/system/greywatch.service"
POLICY_REL="usr/share/polkit-1/actions/greywatch.apply.policy"
UNIT_SYS="/$UNIT_REL"
POLICY_SYS="/$POLICY_REL"

NO_RESTART=0; STAGE=""; CHECK=0; CHECK_DIR=""; UNINSTALL=0; YES=0
while [ $# -gt 0 ]; do
    case "$1" in
        --no-restart) NO_RESTART=1 ;;
        --uninstall)  UNINSTALL=1 ;;
        --yes)        YES=1 ;;
        --root)       [ $# -ge 2 ] || { echo "--root needs a directory" >&2; exit 2; }
                      STAGE="$2"; shift ;;
        --check)      if [ $# -ge 2 ] && [ "${2#-}" = "$2" ]; then CHECK_DIR="$2"; shift; fi
                      CHECK=1 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

subst() { sed "s|__GW_HOME__|$GW|g" "$1"; }

deploy_files() { # $1 = unit destination, $2 = policy destination
    local tmp; tmp="$(mktemp)"
    if ! { subst "$UNIT_TPL" > "$tmp" \
              && install -Dm 0644 "$tmp" "$1" \
              && subst "$POLICY_TPL" > "$tmp" \
              && install -Dm 0644 "$tmp" "$2"; }; then
        rm -f "$tmp"
        echo "install failed while writing $1/$2" >&2
        return 1
    fi
    rm -f "$tmp"
    echo "installed: $1"
    echo "installed: $2"
}

invoker_home() {
    if [ -n "${SUDO_USER:-}" ]; then getent passwd "$SUDO_USER" | cut -d: -f6
    elif [ "$(id -u)" -ne 0 ]; then echo "$HOME"
    else echo ""
    fi
}

icons_user() { # $1 = user home dir
    [ -n "$1" ] || return 1
    env -u SUDO_USER HOME="$1" XDG_DATA_HOME="$1/.local/share" \
        bash "$GW/install-icons.sh"
}

check_icon_tree() { # $1 = home dir containing .local/share + Desktop
    [ -d "$1" ] || { echo "✗ user home tree missing ($1)"; return 1; }
    local data="$1/.local/share" fail=0 s
    for s in 16 24 32 48 64 128 256; do
        [ -f "$data/icons/hicolor/${s}x${s}/apps/greywatch.png" ] \
            || { echo "✗ icon size $s missing under $data/icons/hicolor"; fail=1; }
    done
    grep -q "ui/app.py" "$data/applications/greywatch.desktop" 2>/dev/null \
        || { echo "✗ launcher entry missing in $data/applications"; fail=1; }
    [ -f "$1/Desktop/greywatch.desktop" ] \
        || { echo "✗ desktop shortcut missing in $1/Desktop"; fail=1; }
    [ "$fail" -eq 0 ] && echo "✓ icons + launcher present"
    return "$fail"
}

check_unit_file() { # $1 = unit file path, $2 = 1 for staged strict check
    [ -f "$1" ] || { echo "✗ unit file missing ($1)"; return 1; }
    if grep -q "__GW_HOME__" "$1"; then
        echo "✗ unit still contains the __GW_HOME__ placeholder"; return 1
    fi
    grep -q "ExecStart=/usr/bin/python3 $GW/greywatch_daemon.py" "$1" \
        || { echo "✗ unit ExecStart does not point at $GW/greywatch_daemon.py"; return 1; }
    if [ "${2:-0}" = "1" ]; then
        grep -q "CPUQuota=50%" "$1" && grep -q "MemoryMax=768M" "$1" \
            || { echo "✗ unit lacks the 50%/768M limits"; return 1; }
        grep -q "NoNewPrivileges=true" "$1" \
            || { echo "✗ unit lacks NoNewPrivileges"; return 1; }
        grep -q "nft delete table inet greywatch_appfw" "$1" \
            || { echo "✗ unit lacks the ExecStopPost nftables cleanup"; return 1; }
    fi
    echo "✓ unit file matches this checkout's template"
}

check_policy_file() { # $1 = policy file
    local fail=0 id helper
    [ -f "$1" ] || { echo "✗ polkit policy missing ($1)"; return 1; }
    if grep -q "__GW_HOME__" "$1"; then
        echo "✗ policy still has __GW_HOME__"; return 1
    fi
    while IFS= read -r id; do
        helper="${id##*.}.sh"
        grep -q "action id=\"$id\"" "$1" \
            || { echo "✗ deployed policy lacks action $id"; fail=1; continue; }
        grep -A6 "action id=\"$id\"" "$1" \
            | grep -Fq "exec.path\">$GW/apply/$helper" \
            || { echo "✗ action $id does not allowlist $GW/apply/$helper"; fail=1; }
    done < <(grep -o 'action id="com\.greywatch\.apply\.[a-z-]*"' "$POLICY_TPL" \
              | cut -d'"' -f2)
    [ "$fail" -eq 0 ] && echo "✓ polkit allowlist contains every template helper"
    return "$fail"
}

check_unit_live() {
    local fail=0 k v
    [ "$(systemctl is-active greywatch 2>/dev/null)" = "active" ] \
        || { echo "✗ greywatch.service is not active"; fail=1; }
    [ "$(systemctl is-enabled greywatch 2>/dev/null)" = "enabled" ] \
        || { echo "✗ greywatch.service is not enabled"; fail=1; }
    systemctl show greywatch -p ExecStart 2>/dev/null | grep -q "$GW/greywatch_daemon.py" \
        || { echo "✗ running service's ExecStart is not $GW/greywatch_daemon.py"; fail=1; }
    for pair in "CPUQuotaPerSecUSec=500ms" "MemoryMax=805306368" "Nice=5" \
                "UMask=0077" "NoNewPrivileges=yes" "LockPersonality=yes" \
                "RestrictRealtime=yes" "IOSchedulingClass=2"; do
        k="${pair%%=*}"; v="${pair#*=}"
        [ "$(systemctl show greywatch -p "$k" 2>/dev/null)" = "$k=$v" ] \
            || { echo "✗ live $k is not $v"; fail=1; }
    done
    [ "$fail" -eq 0 ] && echo "✓ live unit matches the template (active, enabled, hardened)"
    return "$fail"
}

do_check() {
    local fail=0 base dir home
    if [ -n "$CHECK_DIR" ]; then
        base="$CHECK_DIR"
        echo "checking staged deployment in $base"
        check_unit_file "$base/$UNIT_REL" 1 || fail=1
        check_policy_file "$base/$POLICY_REL" || fail=1
        check_icon_tree "$base/home" || fail=1
    else
        echo "checking the real system deployment"
        check_unit_file "$UNIT_SYS" 0 || fail=1
        check_policy_file "$POLICY_SYS" || fail=1
        check_unit_live || fail=1
        home="$(invoker_home)"
        [ -n "$home" ] && check_icon_tree "$home" || { echo "✗ user icon tree missing"; fail=1; }
    fi
    if [ "$fail" -eq 0 ]; then echo "install check: everything matches"; return 0; fi
    echo "install check: $fail failure(s) — run sudo ./install.sh to bring the machine back to repo state"
    return 1
}

do_stage() {
    set -e
    deploy_files "$STAGE/$UNIT_REL" "$STAGE/$POLICY_REL" >/dev/null 2>&1
    icons_user "$STAGE/home" >/dev/null 2>&1 || true
    echo "staged full install under $STAGE (no system files touched)"
    echo "self-test: ./install.sh --check --root $STAGE"
}

do_install_root() {
    [ "$(id -u)" -eq 0 ] || { echo "sudo required: ./install.sh (no sudo) only installs user icons"; exit 1; }
    set -e
    deploy_files "$UNIT_SYS" "$POLICY_SYS"
    systemctl daemon-reload
    systemctl enable --now greywatch.service 2>/dev/null || true
    if [ "$NO_RESTART" -eq 0 ]; then
        systemctl try-restart greywatch.service
        echo "restarted greywatch.service to load the new unit"
    fi
    local home; home="$(invoker_home)"
    if [ -n "$home" ]; then
        icons_user "$home" 2>&1 | head -3 || true
        echo "(if the desktop shortcut ever asks to be trusted: run ./install-icons.sh yourself, no sudo)"
    fi
    echo "system install done — verify with: ./install.sh --check"
}

do_uninstall_root() {
    [ "$(id -u)" -eq 0 ] || { echo "uninstall needs sudo" >&2; exit 1; }
    if [ "$YES" -ne 1 ] && [ -t 0 ]; then
        read -r -p "remove greywatch unit + polkit allowlist + launcher? security history in $GW/data is KEPT. [y/N] " ans
        case "$ans" in y|Y) ;; *) echo "aborted"; exit 1 ;; esac
    fi
    set -e
    systemctl disable --now greywatch.service 2>/dev/null || true
    rm -f "$UNIT_SYS" "$POLICY_SYS"
    systemctl daemon-reload
    local home; home="$(invoker_home)"
    if [ -n "$home" ]; then
        rm -f "$home/.local/share/icons/hicolor/"{16,24,32,48,64,128,256}x*/apps/greywatch.png 2>/dev/null || true
        rm -f "$home/.local/share/applications/greywatch.desktop" \
              "$home/Desktop/greywatch.desktop" 2>/dev/null || true
    fi
    echo "system files removed."
    echo "keeps security history: $GW/data (root-owned) — delete manually only if you mean it."
}

if [ "$CHECK" -eq 1 ]; then
    [ -n "$CHECK_DIR" ] || CHECK_DIR="$STAGE"
    do_check
    exit $?
fi
if [ -n "$STAGE" ]; then
    do_stage
    exit 0
fi
if [ "$UNINSTALL" -eq 1 ]; then
    do_uninstall_root
    exit $?
fi
if [ "$(id -u)" -eq 0 ]; then
    do_install_root
else
    echo "no root: installing user icons + launcher only"
    icons_user "$HOME" 2>&1 | head -3
    echo "system unit + polkit policy: run 'sudo ./install.sh'"
fi