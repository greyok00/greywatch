#!/bin/bash
# install.sh — deploy greywatch's system integration.
#
# SECURITY BOUNDARY: code the root daemon executes and every polkit helper
# live in /usr/lib/greywatch, a root-owned, group/other-write-free tree
# copied from this checkout. Runtime state lives in /var/lib/greywatch,
# writable only by root and the desktop user's group. The unit and the
# polkit action paths point at the installed copies — the root daemon
# NEVER runs python straight out of a user-writable checkout.
#
# Modes:
#   sudo ./install.sh               system files + restart, then user icons
#   sudo ./install.sh --no-restart  deploy files, leave the daemon running
#   sudo ./install.sh --uninstall   remove unit + policy + program copy
#                                   (+ launcher); keeps runtime state
#   ./install.sh                    user icons + launcher only (no root)
#   ./install.sh --root DIR         install into a staging dir (self-test only)
#   ./install.sh --check [DIR]      verify a deployment (default: the real system)
#
# Templates: doc/greywatch.service and apply/polkit/greywatch.apply.policy
# carry only __GW_LIB__ (program tree) and __GW_DATA__ (state dir).
set -euo pipefail
GW="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
UNIT_TPL="$GW/doc/greywatch.service"
POLICY_TPL="$GW/apply/polkit/greywatch.apply.policy"
UNIT_REL="etc/systemd/system/greywatch.service"
POLICY_REL="usr/share/polkit-1/actions/greywatch.apply.policy"
MODULES_REL="etc/modules-load.d/greywatch-appfw.conf"
LIB_REL="usr/lib/greywatch"
DATA_REL="var/lib/greywatch"
UNIT_SYS="/$UNIT_REL"
POLICY_SYS="/$POLICY_REL"
MODULES_SYS="/$MODULES_REL"
LIB_SYS="/$LIB_REL"
DATA_SYS="/$DATA_REL"
UI_USER="${GREYWATCH_UI_USER:-${SUDO_USER:-grey}}"

resolve_ui_user() { # resolve + VALIDATE the desktop identity (GW-02):
    # an unknown user must abort the install, not fall back to a guess.
    if [ "$UI_USER" = root ] || [ "$UI_USER" = greywatch ]; then
        echo "ERROR: GREYWATCH_UI_USER='$UI_USER' is not a desktop user." >&2
        echo "       rerun with GREYWATCH_UI_USER=<desktop user>" >&2
        exit 2
    fi
    if ! getent passwd "$UI_USER" >/dev/null; then
        echo "ERROR: desktop user '$UI_USER' does not exist on this system." >&2
        echo "       rerun with GREYWATCH_UI_USER=<desktop user>" >&2
        exit 2
    fi
}

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

# In staging, everything lands under $STAGE; a real install uses the
# fixed system paths. subst() fills the templates with the right pair.
if [ -n "$STAGE" ]; then
    LIB="$STAGE/$LIB_REL"
    DATA="$STAGE/$DATA_REL"
else
    LIB="$LIB_SYS"
    DATA="$DATA_SYS"
fi

subst() { sed -e "s|__GW_LIB__|$LIB|g" -e "s|__GW_DATA__|$DATA|g" \
              -e "s|__GW_UI_USER__|$UI_USER|g" "$1"; }

_copy_program() { # $1 = destination program tree (code, root-owned)
    local dest="$1"
    [ -d "$dest" ] && rm -rf "$dest"
    mkdir -p "$dest"
    tar -C "$GW" -cf - \
        --exclude='./.git' --exclude='./data' --exclude='./tests' \
        --exclude='./build' --exclude='./dist' --exclude='./doc/shots' \
        --exclude='./.venv' --exclude='./venv' --exclude='*.pyc' \
        --exclude='__pycache__' --exclude='./.pytest_cache' \
        --exclude='./.ruff_cache' --exclude='./.mypy_cache' \
        --exclude='./.claude' --exclude='./runbooks' \
        . | tar -C "$dest" -xf -
    if [ "$(id -u)" -eq 0 ] && [ -z "$STAGE" ]; then
        chown -R root:root "$dest"
    fi
    find "$dest" -type d -exec chmod 0755 {} +
    find "$dest" -type f -exec chmod 0644 {} +
    find "$dest" -type f \( -name '*.sh' -o -path '*/bin/*' \) -exec chmod 0755 {} +
    find "$dest" -name '__pycache__' -prune -exec rm -rf {} + 2>/dev/null || true
    echo "program tree installed: $dest"
}

_make_state_dir() { # $1 = destination state dir
    local dest="$1"
    mkdir -p "$dest"
    if [ "$(id -u)" -eq 0 ] && [ -z "$STAGE" ]; then
        # root owns it; the desktop user's group read-writes it (the UI
        # stores paused.json, learning.json, firewall-mode.json there)
        chown "root:$(getent passwd "$UI_USER" | cut -d: -f4)" "$dest"
        chmod 0770 "$dest"
    fi
    echo "runtime state dir ready: $dest"
}

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

deploy_modules() { # $1 = modules-load.d destination
    # The appfw engine needs nfnetlink_queue + nft_queue for its nft
    # 'queue' statement. Loading them at boot means a reboot never strands
    # the engine (the engine also modprobes at arm time as a fallback).
    if ! install -Dm 0644 "$GW/apply/modules-load-greywatch.conf" "$1"; then
        echo "install failed while writing $1" >&2
        return 1
    fi
    echo "installed: $1"
}

invoker_home() {
    if [ -n "${SUDO_USER:-}" ]; then getent passwd "$SUDO_USER" | cut -d: -f6
    elif [ "$(id -u)" -ne 0 ]; then echo "$HOME"
    else echo ""
    fi
}

icons_user() { # $1 = user home dir
    [ -n "$1" ] || return 1
    # XDG_CONFIG_HOME is pinned as well: a caller with it already set (the CI
    # runner does) otherwise puts the autostart entry outside $1 and the
    # staged check below fails on a correct install.
    env -u SUDO_USER HOME="$1" XDG_DATA_HOME="$1/.local/share" \
        XDG_CONFIG_HOME="$1/.config" bash "$GW/install-icons.sh"
}

check_icon_tree() { # $1 = home dir containing .local/share + Desktop
    [ -d "$1" ] || { echo "✗ user home tree missing ($1)"; return 1; }
    local data="$1/.local/share" fail=0 s
    for s in 16 24 32 48 64 128 256; do
        [ -f "$data/icons/hicolor/${s}x${s}/apps/greywatch.png" ] \
            || { echo "✗ icon size $s missing under $data/icons/hicolor"; fail=1; }
    done
    compgen -G "$data/icons/hicolor/scalable/apps/gw-tool-*-symbolic.svg" \
        >/dev/null \
        || { echo "✗ per-tool icons missing under $data/icons/hicolor/scalable"; fail=1; }
    grep -q "ui/app.py" "$data/applications/greywatch.desktop" 2>/dev/null \
        || { echo "✗ launcher entry missing in $data/applications"; fail=1; }
    [ -f "$1/Desktop/greywatch.desktop" ] \
        || { echo "✗ desktop shortcut missing in $1/Desktop"; fail=1; }
    grep -q "ui/app.py" "$1/.config/autostart/greywatch.desktop" 2>/dev/null \
        || { echo "✗ autostart entry missing in $1/.config/autostart"; fail=1; }
    [ "$fail" -eq 0 ] && echo "✓ icons + launcher + autostart present"
    return "$fail"
}

check_program_tree() { # $1 = program tree dir
    local fail=0
    [ -f "$1/greywatch_daemon.py" ] \
        || { echo "✗ program tree missing greywatch_daemon.py ($1)"; return 1; }
    [ -f "$1/apply/unban-ip.sh" ] \
        || { echo "✗ program tree missing the apply/ helpers ($1)"; fail=1; }
    [ -d "$1/ui" ] || { echo "✗ program tree missing ui/ ($1)"; fail=1; }
    # every code path must be closed to other-writes
    local loose
    loose="$(find "$1" -perm -o+w 2>/dev/null)"
    [ -z "$loose" ] || { echo "✗ program tree is other-writable: $loose"; fail=1; }
    [ "$fail" -eq 0 ] && echo "✓ program tree present, not other-writable"
    return "$fail"
}

check_state_dir() { # $1 = runtime state dir
    [ -d "$1" ] || { echo "✗ runtime state dir missing ($1)"; return 1; }
    echo "✓ runtime state dir present ($1)"
    return 0
}

check_modules_file() { # $1 = modules-load.d file path
    [ -f "$1" ] || { echo "✗ modules-load.d file missing ($1)"; return 1; }
    grep -q "^nfnetlink_queue$" "$1" \
        || { echo "✗ modules file lacks nfnetlink_queue"; return 1; }
    grep -q "^nft_queue$" "$1" \
        || { echo "✗ modules file lacks nft_queue"; return 1; }
    echo "✓ modules-load.d file present (nfnetlink_queue, nft_queue)"
}

check_unit_file() { # $1 = unit file path, $2 = 1 for staged strict check
    [ -f "$1" ] || { echo "✗ unit file missing ($1)"; return 1; }
    if grep -q "__GW_LIB__\|__GW_DATA__\|__GW_HOME__" "$1"; then
        echo "✗ unit still contains an unresolved placeholder"; return 1
    fi
    grep -q "ExecStart=/usr/bin/python3 $LIB/greywatch_daemon.py --data-dir $DATA" "$1" \
        || { echo "✗ unit ExecStart does not point at $LIB with $DATA"; return 1; }
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
    if grep -q "__GW_LIB__\|__GW_DATA__\|__GW_HOME__" "$1"; then
        echo "✗ policy still has an unresolved placeholder"; return 1
    fi
    while IFS= read -r id; do
        helper="${id##*.}.sh"
        grep -q "action id=\"$id\"" "$1" \
            || { echo "✗ deployed policy lacks action $id"; fail=1; continue; }
        grep -A6 "action id=\"$id\"" "$1" \
            | grep -Fq "exec.path\">$LIB/apply/$helper" \
            || { echo "✗ action $id does not allowlist $LIB/apply/$helper"; fail=1; }
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
    systemctl show greywatch -p ExecStart 2>/dev/null | grep -qF "$LIB/greywatch_daemon.py" \
        || { echo "✗ running service's ExecStart is not $LIB/greywatch_daemon.py"; fail=1; }
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
        check_program_tree "$base/$LIB_REL" || fail=1
        check_state_dir "$base/$DATA_REL" || fail=1
        check_unit_file "$base/$UNIT_REL" 1 || fail=1
        check_policy_file "$base/$POLICY_REL" || fail=1
        check_modules_file "$base/$MODULES_REL" || fail=1
        check_icon_tree "$base/home" || fail=1
    else
        echo "checking the real system deployment"
        check_program_tree "$LIB_SYS" || fail=1
        check_state_dir "$DATA_SYS" || fail=1
        check_unit_file "$UNIT_SYS" 0 || fail=1
        check_policy_file "$POLICY_SYS" || fail=1
        check_modules_file "$MODULES_SYS" || fail=1
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
    _copy_program "$STAGE/$LIB_REL"
    _make_state_dir "$STAGE/$DATA_REL"
    deploy_files "$STAGE/$UNIT_REL" "$STAGE/$POLICY_REL" >/dev/null 2>&1
    deploy_modules "$STAGE/$MODULES_REL" >/dev/null 2>&1
    icons_user "$STAGE/home" >/dev/null 2>&1 || true
    echo "staged full install under $STAGE (no system files touched)"
    echo "self-test: ./install.sh --check --root $STAGE"
}

do_install_root() {
    [ "$(id -u)" -eq 0 ] || { echo "sudo required: ./install.sh (no sudo) only installs user icons"; exit 1; }
    resolve_ui_user
    set -e
    _copy_program "$LIB_SYS"
    _make_state_dir "$DATA_SYS"
    deploy_files "$UNIT_SYS" "$POLICY_SYS"
    deploy_modules "$MODULES_SYS"
    systemctl daemon-reload
    # load the queue modules NOW so the engine can arm without a reboot
    modprobe nfnetlink_queue 2>/dev/null || true
    modprobe nft_queue 2>/dev/null || true
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
        read -r -p "remove greywatch unit + polkit allowlist + program copy? runtime state in $DATA_SYS is KEPT. [y/N] " ans
        case "$ans" in y|Y) ;; *) echo "aborted"; exit 1 ;; esac
    fi
    set -e
    systemctl disable --now greywatch.service 2>/dev/null || true
    rm -f "$UNIT_SYS" "$POLICY_SYS" "$MODULES_SYS"
    rm -rf "$LIB_SYS"
    systemctl daemon-reload
    local home; home="$(invoker_home)"
    if [ -n "$home" ]; then
        rm -f "$home/.local/share/icons/hicolor/"{16,24,32,48,64,128,256}x*/apps/greywatch.png 2>/dev/null || true
        rm -f "$home/.local/share/applications/greywatch.desktop" \
              "$home/Desktop/greywatch.desktop" \
              "$home/.config/autostart/greywatch.desktop" \
              "$home/.config/autostart/greywatch-tray.desktop" 2>/dev/null || true
    fi
    echo "system files removed."
    echo "keeps runtime state: $DATA_SYS (root-owned) — delete manually only if you mean it."
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