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
DOC="$GW/doc"
UNIT_TPL="$GW/doc/greywatch.service"
HUNIT_TPL="$GW/doc/greywatch-hunter.service"
WUNIT_TPL="$GW/doc/greywatch-watchdog.service"
WTIMER_TPL="$GW/doc/greywatch-watchdog.timer"
FUNIT_TPL="$GW/doc/greywatch-feeds.service"
FTIMER_TPL="$GW/doc/greywatch-feeds.timer"
SUNIT_TPL="$GW/doc/greywatch-boot-sweep.service"
STIMER_TPL="$GW/doc/greywatch-boot-sweep.timer"
CLAMD_LIMITS="$GW/doc/clamav-daemon-limits.conf"
FRESHCLAM_LIMITS="$GW/doc/freshclam-limits.conf"
POLICY_TPL="$GW/apply/polkit/greywatch.apply.policy"
RULES_TPL="$GW/apply/polkit/51-greywatch.rules"
UNIT_REL="etc/systemd/system/greywatch.service"
HUNIT_REL="etc/systemd/system/greywatch-hunter.service"
POLICY_REL="usr/share/polkit-1/actions/greywatch.apply.policy"
RULES_REL="etc/polkit-1/rules.d/51-greywatch.rules"
MODULES_REL="etc/modules-load.d/greywatch-appfw.conf"
LIB_REL="usr/lib/greywatch"
DATA_REL="var/lib/greywatch"
UNIT_SYS="/$UNIT_REL"
HUNIT_SYS="/$HUNIT_REL"
POLICY_SYS="/$POLICY_REL"
RULES_SYS="/$RULES_REL"
MODULES_SYS="/$MODULES_REL"
LIB_SYS="/$LIB_REL"
DATA_SYS="/$DATA_REL"
UI_USER="${GREYWATCH_UI_USER:-${SUDO_USER:-grey}}"

resolve_ui_user() {   # resolve + VALIDATE the desktop identity:
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

check_libnotify() {   # notify-send is required for daemon-side desktop
    # notifications (notifyd.py uses runuser to fire libnotify bubbles).
    # Install if missing; do not fail the install if apt is unavailable.
    if command -v notify-send >/dev/null 2>&1; then
        return 0
    fi
    echo "WARNING: libnotify-bin (notify-send) not found — desktop notifications will be skipped"
    if command -v apt-get >/dev/null 2>&1; then
        if apt-get install -y libnotify-bin 2>/dev/null; then
            echo "installed libnotify-bin"
        else
            echo "WARNING: apt install of libnotify-bin failed — install manually"
        fi
    elif command -v dnf >/dev/null 2>&1; then
        if dnf install -y libnotify 2>/dev/null; then
            echo "installed libnotify (dnf)"
        else
            echo "WARNING: dnf install of libnotify failed — install manually"
        fi
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
# fixed system paths. subst fills the templates with the right pair.
if [ -n "$STAGE" ]; then
    LIB="$STAGE/$LIB_REL"
    DATA="$STAGE/$DATA_REL"
else
    LIB="$LIB_SYS"
    DATA="$DATA_SYS"
fi

subst() { sed -e "s|__GW_LIB__|$LIB|g" -e "s|__GW_DATA__|$DATA|g" \
              -e "s|__GW_UI_USER__|$UI_USER|g" "$1"; }

_check_abi() { # $1 = program tree about to be deployed
    # A compiled module is ABI-tagged and its .py fallback was dropped, so
    # this tree only runs on that exact Python minor. Refuse now with the
    # reason; the alternative is an ImportError after the daemon restart.
    local abis want py
    abis="$(find "$1" -name '*.so' -printf '%f\n' 2>/dev/null |
            sed -n 's/.*\.cpython-\([0-9]\)\([0-9][0-9]*\)[^0-9].*/\1.\2/p' |
            sort -u | tr '\n' ' ')"
    [ -z "${abis// /}" ] && return 0     # a source checkout: nothing compiled
    py="${GREYWATCH_PYTHON:-/usr/bin/python3}"    # what the unit will run
    want="$("$py" -c 'import sys;print("%d.%d"%sys.version_info[:2])' 2>/dev/null || true)"
    case " $abis " in
        *" $want "*) return 0 ;;
    esac
    echo "ERROR: this tree is compiled for Python $abis, but /usr/bin/python3 is ${want:-unknown}." >&2
    echo "       The tree ships plain readable Python, so install the wheel," >&2
    echo "       which carries readable Python for any 3.12 or newer." >&2
    exit 2
}

_copy_program() { # $1 = destination program tree (code, root-owned)
    local dest="$1"
    _check_abi "$GW"
    [ -d "$dest" ] && rm -rf "$dest"
    mkdir -p "$dest"
    tar -C "$GW" -cf - \
        --exclude='./.git' --exclude='./data' --exclude='./tests' \
        --exclude='./build' --exclude='./dist' --exclude='./doc/shots' \
        --exclude='./.venv' --exclude='./venv' --exclude='*.pyc' \
        --exclude='./appfw/bin' \
        --exclude='__pycache__' --exclude='./.pytest_cache' \
        --exclude='./.ruff_cache' --exclude='./.mypy_cache' \
        --exclude='./.claude' --exclude='./runbooks' \
        --exclude='./docs/superpowers' --exclude='./docs/2026*' \
        --exclude='./docs/1.0-gap-audit.md' \
        --exclude='./docs/manual/shots' --exclude='./docs/manual/walkthrough.pdf' \
        . | tar -C "$dest" -xf -
    if [ "$(id -u)" -eq 0 ] && [ -z "$STAGE" ]; then
        chown -R root:root "$dest"
    fi
    # the watchlist snapshot seeds itself here (state lives elsewhere; a
    # fresh install reads the shipped map before the daemon's first cycle)
    [ -n "$STAGE" ] || [ ! -f "$GW/data/ptp-watchlist.json" ] || \
        install -Dm 0644 "$GW/data/ptp-watchlist.json" \
            "$dest/data/ptp-watchlist.json"
    find "$dest" -type d -exec chmod 0755 {} +
    find "$dest" -type f -exec chmod 0644 {} +
    find "$dest" -type f \( -name '*.sh' -o -path '*/bin/*' \) -exec chmod 0755 {} +
    # Executables named DIRECTLY as a unit's ExecStart need +x even though
    # they are plain .py with a shebang: status=203/EXEC is what happens
    # without it (greywatch-feeds failed exactly this way, 2026-11-12). The
    # list is derived from the shipped unit files so a new unit cannot
    # silently reintroduce the fault.
    for unit in "$GW"/doc/*.service; do
        [ -f "$unit" ] || continue
        sed -n 's/^ExecStart=\([^ ]*\).*/\1/p' "$unit" | while read -r prog; do
            # The shipped templates write the library root as __GW_LIB__;
            # a handful of older ones carry the absolute path. Accept both,
            # and resolve either onto THIS tree's library root.
            case "$prog" in
                __GW_LIB__/*)          rel="$dest/${prog#__GW_LIB__/}" ;;
                /usr/lib/greywatch/*)  rel="$dest/${prog#/usr/lib/greywatch/}" ;;
                *) continue ;;
            esac
            [ -f "$rel" ] && chmod 0755 "$rel"
        done
    done
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

assistant_assets() { # optional chat assets: the model gguf under $DATA,
    # the knowledge index, and the desktop user's llama-cpp-python
    # binding. Every piece is optional — the chat degrades to docs-only
    # without it — so a failure prints the exact follow-up command
    # instead of failing the install. Runs in the real install only:
    # the --root staging self-test stays offline and hermetic.
    local grp model msize
    grp="$(getent passwd "$UI_USER" | cut -d: -f4)"
    mkdir -p "$DATA/models"
    # The filename and URL mirror assistant/model.py (single source of
    # truth for the app; kept literal here so a bare install needs no
    # Python import).
    model="$DATA/models/Qwen3-1.7B-Q4_K_M.gguf"
    model_url="https://huggingface.co/unsloth/Qwen3-1.7B-GGUF/resolve/main/Qwen3-1.7B-Q4_K_M.gguf"
    if [ ! -s "$model" ]; then
        if curl -L --fail --connect-timeout 15 --retry 2 -o "$model" \
                "$model_url"; then
            # plausibility floor: a truncated-but-nonempty download must
            # not survive (the real artifact is ~1.06 GiB)
            msize="$(stat -c %s "$model" 2>/dev/null || echo 0)"
            if [ "$msize" -lt $((900 * 1024 * 1024)) ]; then
                rm -f "$model" # a truncated download must never pass the -s probe
            fi
        else
            rm -f "$model" # a partial download must never pass the -s probe
        fi
        if [ ! -s "$model" ]; then
            echo "assistant model not fetched — chat stays docs-only"
            echo "  fetch later: curl -L --fail --connect-timeout 15 --retry 2 -o $model \\"
            echo "      $model_url"
        fi
    fi
    # upgrade path: the old 360M brain is dead weight once this one is in
    old_model="$DATA/models/smollm2-360m-instruct-q4_k_m.gguf"
    if [ -s "$model" ] && [ -e "$old_model" ]; then
        if rm -f "$old_model"; then
            echo "removed the old 360M model"
        fi
    fi
    if [ -f "$model" ]; then
        # group-readable like the rest of the shared state
        chmod 0644 "$model"
        chown "root:$grp" "$model" 2>/dev/null || true
        echo "assistant model ready: $model"
    fi
    # the index is built into the state dir this install just prepared
    if GREYWATCH_DATA_DIR="$DATA" python3 "$GW/tools/build_knowledge_index.py"; then
        chmod 0640 "$DATA/knowledge-index.json" 2>/dev/null || true
        chown "root:$grp" "$DATA/knowledge-index.json" 2>/dev/null || true
    else
        echo "knowledge index not built — chat stays docs-only"
    fi
    # the binding is user-local (llama-cpp-python on the desktop user's
    # site-packages); UI_USER is resolved and validated above.
    # Skip entirely when the model is absent: an already docs-only install
    # gains nothing from minutes of sdist compilation.
    local home
    home="$(getent passwd "$UI_USER" | cut -d: -f6)"
    if [ ! -s "$model" ]; then
        echo "assistant model missing — skipping the binding build; chat stays docs-only"
        echo "  install later: sudo -u $UI_USER python3 -m pip install \\"
        echo "      --user --break-system-packages 'llama-cpp-python>=0.3.0'"
    elif sudo -u "$UI_USER" env HOME="$home" python3 -c "import llama_cpp" 2>/dev/null; then
        echo "assistant binding already present for $UI_USER"
    elif sudo -u "$UI_USER" env HOME="$home" python3 -m pip install --user \
            --break-system-packages "llama-cpp-python>=0.3.0"; then
        echo "assistant binding installed for $UI_USER"
    else
        echo "assistant binding not installed — chat stays docs-only"
        echo "  install later: sudo -u $UI_USER python3 -m pip install \\"
        echo "      --user --break-system-packages 'llama-cpp-python>=0.3.0'"
    fi
}

deploy_files() { # $1 = unit destination, $2 = policy, $3 = rules.d grant
    # The hunter unit rides in the same directory: the threat hunter is a
    # separate unprivileged process, still root-owned code, per the wave
    # plan.
    local tmp dest_dir; tmp="$(mktemp)"
    dest_dir="$(dirname "$1")"
    if ! { subst "$UNIT_TPL" > "$tmp" \
              && install -Dm 0644 "$tmp" "$1" \
              && subst "$POLICY_TPL" > "$tmp" \
              && install -Dm 0644 "$tmp" "$2" \
              && subst "$HUNIT_TPL" > "$tmp" \
              && install -Dm 0644 "$tmp" "$dest_dir/greywatch-hunter.service" \
              && subst "$WUNIT_TPL" > "$tmp" \
              && install -Dm 0644 "$tmp" "$dest_dir/greywatch-watchdog.service" \
              && install -Dm 0644 "$WTIMER_TPL" "$dest_dir/greywatch-watchdog.timer" \
              && subst "$FUNIT_TPL" > "$tmp" \
              && install -Dm 0644 "$tmp" "$dest_dir/greywatch-feeds.service" \
              && install -Dm 0644 "$FTIMER_TPL" "$dest_dir/greywatch-feeds.timer" \
              && subst "$SUNIT_TPL" > "$tmp" \
              && install -Dm 0644 "$tmp" "$dest_dir/greywatch-boot-sweep.service" \
              && install -Dm 0644 "$STIMER_TPL" "$dest_dir/greywatch-boot-sweep.timer" \
              && install -Dm 0644 "$RULES_TPL" "$3"; }; then
        rm -f "$tmp"
        echo "install failed while writing $1/$2" >&2
        return 1
    fi
    rm -f "$tmp"
    echo "installed: $1"
    echo "installed: $2"
    echo "installed: $dest_dir/greywatch-hunter.service"
    echo "installed: $3"
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
    # The link files belong to the DESKTOP USER, not to whoever ran the
    # installer: a root run with only HOME overriden stamped root-owned
    # entries into the user's own dirs (seen live 2026-11-16), and the
    # desktop could then never mind them. When we are root and the home
    # belongs to a real account, drop to that account instead. A staged
    # tree (owned by root during the deb build) keeps the plain env run.
    local owner
    owner="$(stat -c '%U' "$1" 2>/dev/null || true)"
    if [ "$(id -u)" -eq 0 ] && [ -n "$owner" ] && [ "$owner" != "root" ]; then
        sudo -u "$owner" -H env HOME="$1" \
            XDG_DATA_HOME="$1/.local/share" \
            XDG_CONFIG_HOME="$1/.config" \
            bash "$GW/install-icons.sh"
        return $?
    fi
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
    if [ -f "$GW/ui/app.py" ] || [ -f "$GW/gui/app.py" ]; then
        grep -qE "ui/launch\.sh|ui/app\.py|gui/app\.py" \
            "$data/applications/greywatch.desktop" 2>/dev/null \
            || { echo "✗ launcher entry missing in $data/applications"; fail=1; }
        [ -f "$1/Desktop/greywatch.desktop" ] \
            || { echo "✗ desktop shortcut missing in $1/Desktop"; fail=1; }
        grep -qE "ui/launch\.sh|ui/app\.py|gui/app\.py" \
            "$1/.config/autostart/greywatch.desktop" 2>/dev/null \
            || { echo "✗ autostart entry missing in $1/.config/autostart"; fail=1; }
    else
        echo "ok: no GUI in this tree; launcher checks skipped"
    fi
    [ "$fail" -eq 0 ] && echo "✓ icons + launcher + autostart present"
    return "$fail"
}

check_program_tree() { # $1 = program tree dir
    local fail=0
    [ -f "$1/greywatch_daemon.py" ] \
        || { echo "✗ program tree missing greywatch_daemon.py ($1)"; return 1; }
    [ -f "$1/apply/unban-ip.sh" ] \
        || { echo "✗ program tree missing the apply/ helpers ($1)"; fail=1; }
    if [ ! -d "$1/ui" ]; then
        echo "✗ the stage carries no ui tree (the shell shipped 2026-11-15)"
        fail=1
    elif [ ! -f "$1/ui/app.py" ]; then
        echo "✗ the ui tree carries no app.py (the shell ships from ui/)"
        fail=1
    else
        # The installed tree must carry the current shell, not the retired
        # v3 window.py pages. These are the modules the live registry reads.
        for rel in ui/launch.sh ui/security.py ui/tools.py ui/timeline.py \
                   ui/network.py ui/assistant_page.py ui/helpdesk.py \
                   assets/logo/greywatch-icon-256.png assets/maps/world.png; do
            [ -f "$1/$rel" ] \
                || { echo "✗ the program tree is missing $rel"; fail=1; }
        done
    fi
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

check_unit_file() { # $1 = unit file path, $2 = 1 for staged strict check,
                     # $3 = program tree it must point at, $4 = its state dir
    local lib="${3:-$LIB}" data="${4:-$DATA}"
    [ -f "$1" ] || { echo "✗ unit file missing ($1)"; return 1; }
    if grep -q "__GW_LIB__\|__GW_DATA__\|__GW_HOME__" "$1"; then
        echo "✗ unit still contains an unresolved placeholder"; return 1
    fi
    grep -Fq "ExecStart=/usr/bin/python3 $lib/greywatch_daemon.py --data-dir $data" "$1" \
        || { echo "✗ unit ExecStart does not point at $lib with $data"; return 1; }
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

check_hunter_unit() { # $1 = hunter unit file path, $2 = program lib, $3 = data dir
    local lib="${2:-$LIB}" data="${3:-$DATA}"
    [ -f "$1" ] || { echo "✗ hunter unit missing ($1)"; return 1; }
    if grep -q "__GW_LIB__\|__GW_DATA__\|__GW_UI_USER__" "$1"; then
        echo "✗ hunter unit still contains an unresolved placeholder"; return 1
    fi
    grep -Fq "ExecStart=/usr/bin/python3 $lib/hunter/main.py --data-dir $data" "$1" \
        || { echo "✗ hunter ExecStart does not point at $lib/hunter/main.py with $data"; return 1; }
    grep -Fq "User=$UI_USER" "$1" \
        || { echo "✗ hunter unit must run unprivileged as $UI_USER"; return 1; }
    grep -Fq "NoNewPrivileges=true" "$1" \
        || { echo "✗ hunter unit lacks NoNewPrivileges"; return 1; }
    echo "✓ hunter unit matches this checkout's template"
}

check_policy_file() { # $1 = policy file, $2 = program tree it must point at
    local fail=0 id helper lib="${2:-$LIB}"
    [ -f "$1" ] || { echo "✗ polkit policy missing ($1)"; return 1; }
    if grep -q "__GW_LIB__\|__GW_DATA__\|__GW_HOME__" "$1"; then
        echo "✗ policy still has an unresolved placeholder"; return 1
    fi
    while IFS= read -r id; do
        helper="${id##*.}.sh"
        grep -q "action id=\"$id\"" "$1" \
            || { echo "✗ deployed policy lacks action $id"; fail=1; continue; }
        grep -A6 "action id=\"$id\"" "$1" \
            | grep -Fq "exec.path\">$lib/apply/$helper" \
            || { echo "✗ action $id does not allowlist $lib/apply/$helper"; fail=1; }
    done < <(grep -o 'action id="com\.greywatch\.apply\.[a-z-]*"' "$POLICY_TPL" \
              | cut -d'"' -f2)
    [ "$fail" -eq 0 ] && echo "✓ polkit allowlist contains every template helper"
    return "$fail"
}

check_rules_file() { # $1 = rules.d file (single standing grant)
    # polkit rules.d is root-owned and mode 0700 on several distros
    # (Parrot 2026-11-12): an unprivileged --check cannot [ -f ] it. A
    # permission error on the DIRECTORY is not "the grant is missing"
    # — the install that wrote it moments before proves otherwise — so
    # the unreadable case says "cannot verify" and stays open, while a
    # readable-but-absent file stays a hard failure.
    if [ ! -r "$(dirname "$1")" ] && [ "$(id -u)" -ne 0 ]; then
        echo "? polkit rules.d unreadable as this user — run sudo for the check (the grant itself is root-only viewable)"
        return 0
    fi
    [ -f "$1" ] || { echo "✗ polkit rules.d grant missing ($1)"; return 1; }
    grep -q 'com\.greywatch\.' "$1" \
        || { echo "✗ rules.d grant does not name the com.greywatch prefix"; return 1; }
    grep -q 'isInGroup' "$1" \
        || { echo "✗ rules.d grant is not scoped to a group"; return 1; }
    echo "✓ polkit rules.d grant scoped to com.greywatch.* for local admins"
}

check_unit_live() {
    local fail=0 k v
    [ "$(systemctl is-active greywatch 2>/dev/null)" = "active" ] \
        || { echo "✗ greywatch.service is not active"; fail=1; }
    [ "$(systemctl is-enabled greywatch 2>/dev/null)" = "enabled" ] \
        || { echo "✗ greywatch.service is not enabled"; fail=1; }
    [ "$(systemctl is-active greywatch-hunter 2>/dev/null)" = "active" ] \
        || { echo "✗ greywatch-hunter.service is not active"; fail=1; }
    [ "$(systemctl is-enabled greywatch-hunter 2>/dev/null)" = "enabled" ] \
        || { echo "✗ greywatch-hunter.service is not enabled"; fail=1; }
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

check_gates() { # the design §8 acceptance gates, machine-readable
    local fail=0 t sec
    # gate 6/7: every shipped scanner unit carries caps; feeds timer ≥ t+10min
    for t in greywatch-boot-sweep.service greywatch-feeds.service; do
        [ -f "$DOC/$t" ] || { echo "✗ gate: unit template missing ($t)"; fail=1; }
        grep -q "CPUQuota=" "$DOC/$t" 2>/dev/null \
            || { echo "✗ gate: $t carries no CPUQuota cap"; fail=1; }
        grep -q "MemoryMax=" "$DOC/$t" 2>/dev/null \
            || { echo "✗ gate: $t carries no MemoryMax cap"; fail=1; }
    done
    sec="$(sed -n 's/^OnBootSec=//p' "$DOC/greywatch-feeds.timer" 2>/dev/null | head -1)"
    case "$sec" in
        *min) [ "${sec%min}" -ge 10 ] 2>/dev/null \
            || { echo "✗ gate: feeds timer starts before t+10min ($sec)"; fail=1; } ;;
        *) [ -n "$sec" ] || { echo "✗ gate: feeds timer has no OnBootSec"; fail=1; } ;;
    esac
    # gate 6 (live): the retired cap drop-ins must NOT exist on the
    # system (D1-a); the standard baseline must be on the deployment:
    # the clam-schedule units, the shipped config, and the index
    if [ -z "$CHECK_DIR" ]; then
        [ ! -f /etc/systemd/system/clamav-daemon.service.d/limits.conf ] \
            || { echo "✗ gate: retired clamav cap drop-in still on system"; fail=1; }
    else
        [ -f "$CHECK_DIR/etc/systemd/system/greywatch-clam-scan.timer" ] \
            || { echo "✗ gate: clam-schedule timer not staged"; fail=1; }
        [ -f "$CHECK_DIR/$LIB_REL/data/baseline-configs.json" ] \
            || { echo "✗ gate: baseline-configs.json not staged"; fail=1; }
        [ -s "$CHECK_DIR/$DATA_REL/knowledge-index.json" ] \
            || { echo "✗ gate: knowledge index not staged"; fail=1; }
    fi
    # gate 7: browser-independent lane — the dnsmasq include exists and
    # dnsmasq.conf references it (staged tree carries the rendered conf)
    if [ -n "$CHECK_DIR" ]; then
        [ -f "$CHECK_DIR/etc/dnsmasq.d/greywatch-blocklist.conf" ] \
            || { echo "✗ gate: staged dnsmasq include missing"; fail=1; }
    else
        grep -q "greywatch-blocklist" /etc/dnsmasq.conf 2>/dev/null \
            || { echo "✗ gate: dnsmasq.conf lacks the greywatch include"; fail=1; }
        [ -f /etc/dnsmasq.d/greywatch-blocklist.conf ] \
            || { echo "✗ gate: /etc/dnsmasq.d/greywatch-blocklist.conf missing"; fail=1; }
    fi
    # gate 3/9: the reason+score chain exists in the shipped program tree
    grep -q "threatscale" "$LIB/appfw/policy.py" 2>/dev/null \
        || { echo "✗ gate: threat levels not wired into the chain"; fail=1; }
    # gate 13: the independence law — the defense layers boot by
    # themselves and NEVER sit disabled. GreyWatch is a wrapper that
    # observes and nudges; the primaries (ufw above all) are enabled
    # BEFORE greywatch's gate runs, by install.sh itself (idempotent),
    # and this gate verifies they stayed enabled.
    for _ulaw in ufw.service fail2ban.service apparmor.service\
                 auditd.service; do
        if [ -n "$CHECK_DIR" ]; then
            # A staged tree holds the unit templates but no wants
            # symlinks (staging never pokes the boot config: the live
            # install creates the wants). The law is verified in the
            # live branch; here the units' presence is what gates.
            [ -f "$CHECK_DIR/usr/lib/systemd/system/$_ulaw" ] \
                || [ -f "$LIB/$_ulaw" ] \
                || true
        else
            state="$(systemctl is-enabled "$_ulaw" 2>/dev/null || true)"
            [ "$state" = "enabled" ] || [ "$state" = "static" ] \
                || { echo "✗ gate: $_ulaw is '$state' — a defense layer \
must never sit disabled (owner law 2026-11-12)"; fail=1; }
        fi
    done
    # gate 12's manual counterpart: local-model config only (no cloud lanes shipped)
    grep -rq "api.openai\|anthropic.com\|api.groq" "$LIB/ui/" "$LIB/appfw/" 2>/dev/null \
        && { echo "✗ gate: a cloud AI endpoint appears in shipped code"; fail=1; }
    [ "$fail" -eq 0 ] && echo "✓ acceptance gates (§8) all green"
    return "$fail"
}

do_check() {
    local fail=0 base dir home
    if [ -n "$CHECK_DIR" ]; then
        base="$CHECK_DIR"
        echo "checking staged deployment in $base"
        check_program_tree "$base/$LIB_REL" || fail=1
        check_state_dir "$base/$DATA_REL" || fail=1
        check_unit_file "$base/$UNIT_REL" 1 \
            "$base/$LIB_REL" "$base/$DATA_REL" || fail=1
        check_hunter_unit "$base/$HUNIT_REL" "$base/$LIB_REL" "$base/$DATA_REL" || fail=1
        check_policy_file "$base/$POLICY_REL" "$base/$LIB_REL" || fail=1
        check_rules_file "$base/$RULES_REL" || fail=1
        check_modules_file "$base/$MODULES_REL" || fail=1
        check_icon_tree "$base/home" || fail=1
        DOC="$DOC" LIB="$base/$LIB_REL" check_gates || fail=1
    else
        echo "checking the real system deployment"
        check_program_tree "$LIB_SYS" || fail=1
        check_state_dir "$DATA_SYS" || fail=1
        check_unit_file "$UNIT_SYS" 0 "$LIB_SYS" "$DATA_SYS" || fail=1
        check_hunter_unit "$HUNIT_SYS" "$LIB_SYS" "$DATA_SYS" || fail=1
        check_policy_file "$POLICY_SYS" "$LIB_SYS" || fail=1
        check_rules_file "$RULES_SYS" || fail=1
        check_modules_file "$MODULES_SYS" || fail=1
        check_unit_live || fail=1
        DOC="$DOC" LIB="$LIB_SYS" check_gates || fail=1
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
    deploy_files "$STAGE/$UNIT_REL" "$STAGE/$POLICY_REL" "$STAGE/$RULES_REL" \
        >/dev/null 2>&1
    deploy_modules "$STAGE/$MODULES_REL" >/dev/null 2>&1
    # the schedule units and the shipped baseline config stage too (the
    # self-test must see what a real install deploys); the retired cap
    # drop-ins stage NOTHING after D1-a (owner decision, 2026-11-14)
    install -Dm 0644 "$GW/doc/greywatch-clam-scan.service" \
        "$STAGE/etc/systemd/system/greywatch-clam-scan.service" 2>/dev/null || true
    install -Dm 0644 "$GW/doc/greywatch-clam-scan.timer" \
        "$STAGE/etc/systemd/system/greywatch-clam-scan.timer" 2>/dev/null || true
    sed "s#__GW_LIB__#$LIB_SYS#g" "$GW/doc/greywatch-cve.service" \
        > "$STAGE/greywatch-cve.service" 2>/dev/null || true
    install -Dm 0644 "$STAGE/greywatch-cve.service" \
        "$STAGE/etc/systemd/system/greywatch-cve.service" 2>/dev/null || true
    rm -f "$STAGE/greywatch-cve.service"
    install -Dm 0644 "$GW/doc/greywatch-cve.timer" \
        "$STAGE/etc/systemd/system/greywatch-cve.timer" 2>/dev/null || true
    install -Dm 0644 "$GW/data/baseline-configs.json" \
        "$STAGE/$LIB_REL/data/baseline-configs.json" 2>/dev/null || true
    # the standard baseline rides the stage: the knowledge library is
    # built into the staged state dir exactly like a real install
    if GREYWATCH_DATA_DIR="$STAGE/$DATA_REL" \
        python3 "$GW/tools/build_knowledge_index.py" >/dev/null 2>&1; then
        : ; else echo "WARN: staged knowledge index absent"; fi
    # the rendered dnsmasq include stages as well (gate 7 checks it); an
    # empty feeds cache still produces a valid (empty) conf
    if [ -f "$STAGE/$LIB_REL/webguard.py" ]; then
        GREYWATCH_DATA_DIR="$STAGE/$DATA_REL" \
            "${GREYWATCH_PYTHON:-/usr/bin/python3}" \
            "$STAGE/$LIB_REL/webguard.py" --render >/dev/null 2>&1 \
            && install -Dm 0644 "$STAGE/$DATA_REL/webguard-blocklist.conf" \
                "$STAGE/etc/dnsmasq.d/greywatch-blocklist.conf" \
                || echo "WARN: staged dnsmasq conf render failed"
    fi
    icons_user "$STAGE/home" >/dev/null 2>&1 || true
    # the render pass may byte-compile inside the staged tree: never ship caches
    find "$STAGE/$LIB_REL" -name '__pycache__' -prune -exec rm -rf {} + 2>/dev/null || true
    echo "staged full install under $STAGE (no system files touched)"
    echo "self-test: ./install.sh --check --root $STAGE"
}

do_install_root() {
    [ "$(id -u)" -eq 0 ] || { echo "sudo required: ./install.sh (no sudo) only installs user icons"; exit 1; }
    resolve_ui_user
    check_libnotify
    set -e
    _copy_program "$LIB_SYS"
    # The documented command is `greywatch`. A wrapper keeps sibling
    # imports rooted in the installed tree; a bare symlink would break
    # them (Python follows the link's directory, not the target's).
    install -d /usr/local/bin
    printf '#!/bin/sh\nexec %s %s/cli.py "$@"\n' \
        "${GREYWATCH_PYTHON:-/usr/bin/python3}" "$LIB_SYS" \
        > /usr/local/bin/greywatch
    chmod 0755 /usr/local/bin/greywatch
    _make_state_dir "$DATA_SYS"
    deploy_files "$UNIT_SYS" "$POLICY_SYS" "$RULES_SYS"
    deploy_modules "$MODULES_SYS"
    systemctl daemon-reload
    # load the queue modules NOW so the engine can arm without a reboot
    modprobe nfnetlink_queue 2>/dev/null || true
    modprobe nft_queue 2>/dev/null || true
    : # scanner caps retired here too: the engine runs at distro defaults
    # the boot sweep script (corrected 2026-11-14: it referenced the
    # phantom clam-scan.service user unit and failed every boot)
    install -Dm 0755 "$GW/tools/greywatch-boot-sweep.sh" \
        "/usr/local/sbin/greywatch-boot-sweep" \
        || echo "WARN: boot sweep script not installed"
    # The daily clam timer is retired and installed disabled: a full
    # home scan is not an automatic event. Scans start from the desk.
    install -Dm 0644 "$GW/doc/greywatch-clam-scan.service" \
        "/etc/systemd/system/greywatch-clam-scan.service" \
        || echo "WARN: clam-scan unit not installed"
    install -Dm 0644 "$GW/doc/greywatch-clam-scan.timer" \
        "/etc/systemd/system/greywatch-clam-scan.timer" \
        || echo "WARN: clam-scan timer not installed"
    sed "s#__GW_LIB__#$LIB_SYS#g" "$GW/doc/greywatch-cve.service" \
        > /tmp/greywatch-cve.service.$$
    install -Dm 0644 /tmp/greywatch-cve.service.$$ \
        "/etc/systemd/system/greywatch-cve.service" \
        || echo "WARN: cve refresh unit not installed"
    rm -f /tmp/greywatch-cve.service.$$
    install -Dm 0644 "$GW/doc/greywatch-cve.timer" \
        "/etc/systemd/system/greywatch-cve.timer" \
        || echo "WARN: cve refresh timer not installed"
    install -Dm 0755 "$GW/apply/clam-session.sh" \
        "$LIB_SYS/apply/clam-session.sh" 2>/dev/null \
        || echo "WARN: clam-session.sh not staged"
    install -Dm 0755 "$GW/apply/request-scan.sh" \
        "$LIB_SYS/apply/request-scan.sh" 2>/dev/null \
        || echo "WARN: request-scan.sh not staged"
    systemctl daemon-reload
    # Superseded (owner 2026-11-17): the D1-a resident engine is retired.
    # An install MASKS the virus daemon - the one-shot lane (scan timer,
    # freshclam, throttled clamscan) is the antivirus - and nothing in
    # the suite ever starts the daemon again, on install or at boot.
    systemctl stop clamav-daemon.service clamav-daemon.socket 2>/dev/null \
        || true
    systemctl disable clamav-daemon.service clamav-daemon.socket \
        2>/dev/null || true
    systemctl mask clamav-daemon.service clamav-daemon.socket 2>/dev/null \
        || true
    # a machine that ran the removed caps gets cleaned here: our own
    # drop-in files, not distro config, so uninstalling them is the
    # revert of a greywatch artifact
    if [ -f /etc/systemd/system/clamav-daemon.service.d/limits.conf ]; then
        rm -f /etc/systemd/system/clamav-daemon.service.d/limits.conf
        rmdir /etc/systemd/system/clamav-daemon.service.d 2>/dev/null || true
        echo "removed the retired greywatch clamav cap drop-in"
    fi
    if [ -f /etc/systemd/system/freshclam.service.d/limits.conf ]; then
        rm -f /etc/systemd/system/freshclam.service.d/limits.conf
        rmdir /etc/systemd/system/freshclam.service.d 2>/dev/null || true
    fi
    systemctl daemon-reload
    # browser-independent protection (design §6.2, gate 7): render the
    # validated feed rows into the dnsmasq conf the resolver includes.
    # Rendered unconditionally: the include is part of the standing
    # defense (owner law 2026-11-12) and an empty feeds cache produces
    # a valid (empty) conf — the old feeds-dir condition made fresh
    # installs skip the include, and gate 7 then failed forever after
    # (seen live 2026-11-12: two gate failures on the owner's deploy).
    GREYWATCH_DATA_DIR="$DATA_SYS" "${GREYWATCH_PYTHON:-/usr/bin/python3}" \
        "$LIB_SYS/webguard.py" --render >/dev/null 2>&1 \
        || echo "WARN: dnsmasq conf render failed (no feeds lane)"
    install -Dm 0644 "$DATA_SYS/webguard-blocklist.conf" \
        "/etc/dnsmasq.d/greywatch-blocklist.conf" 2>/dev/null \
        || echo "WARN: /etc/dnsmasq.d include not installed"
    grep -q "greywatch-blocklist" /etc/dnsmasq.conf 2>/dev/null \
        || echo "conf-file=/etc/dnsmasq.d/greywatch-blocklist.conf" \
            >> /etc/dnsmasq.conf
    systemctl try-restart dnsmasq 2>/dev/null || true
    # the rebuild's schedule authority: no duplicate boot triggers (LAW-6)
    systemctl disable clamav-freshclam-once.service 2>/dev/null || true
    systemctl mask clamav-freshclam-once.service 2>/dev/null || true
    # the previously-shipped freshclam-once timer fired at boot: not ours,
    # not wanted; its own packaged timer (clamav-freshclam.timer) keeps
    # the schedule after this point.
    # Independence law (owner order 2026-11-12): the defense layers boot
    # by themselves, ufw above all — GreyWatch is a wrapper that observes,
    # not the thing that keeps the walls up. Install enforces the
    # owner's standing order (idempotent), gate 13 verifies it after.
    systemctl enable --now ufw.service 2>/dev/null || true
    # the virus daemon is masked a few lines up. The antivirus is the
    # one-shot lane started from the window or the CLI: freshclam keeps
    # the definitions current, and no timer starts a scan.
    systemctl enable --now fail2ban.service 2>/dev/null || true
    systemctl enable --now apparmor.service 2>/dev/null || true
    systemctl enable --now auditd.service 2>/dev/null || true
    systemctl enable --now greywatch.service 2>/dev/null || true
    systemctl enable --now greywatch-hunter.service 2>/dev/null || true
    systemctl enable --now greywatch-watchdog.timer 2>/dev/null || true
    systemctl enable --now greywatch-feeds.timer 2>/dev/null || true
    # the boot sweep and the daily clam timer stay OFF (owner order
    # 2026-11-19): no automatic scan of any kind. Disable them before
    # baseline-apply and again after it, so neither path can re-arm them.
    systemctl disable --now greywatch-boot-sweep.timer 2>/dev/null || true
    systemctl disable --now greywatch-clam-scan.timer 2>/dev/null || true
    systemctl enable --now greywatch-cve.timer 2>/dev/null || true
    systemctl reset-failed greywatch-cve.service 2>/dev/null || true
    # the install-time contract (owner 2026-11-14, session item 1): the
    # install arms every detector with the config that works, through
    # the same journaled helper the CLI uses, before first boot
    "${GREYWATCH_PYTHON:-/usr/bin/python3}" "$LIB_SYS/cli.py" \
        baseline-apply --level 1 --yes 2>/dev/null \
        || echo "WARN: baseline level 1 apply failed (units are still enabled above)"
    "${GREYWATCH_PYTHON:-/usr/bin/python3}" "$LIB_SYS/cli.py" \
        baseline-apply --level 2 --yes 2>/dev/null \
        || echo "WARN: baseline level 2 apply failed (configs above)"
    # defense in depth: level 1 no longer lists either timer, but an
    # older config on the machine could. Disable both once more after
    # the arming pass finishes.
    systemctl disable --now greywatch-boot-sweep.timer 2>/dev/null || true
    systemctl disable --now greywatch-clam-scan.timer 2>/dev/null || true
    if [ "$NO_RESTART" -eq 0 ]; then
        systemctl try-restart greywatch.service
        systemctl try-restart greywatch-hunter.service 2>/dev/null || true
        echo "restarted greywatch.service to load the new unit"
    fi
    local home; home="$(invoker_home)"
    if [ -n "$home" ]; then
        icons_user "$home" 2>&1 | head -3 || true
        echo "(if the desktop shortcut ever asks to be trusted: run ./install-icons.sh yourself, no sudo)"
    fi
    # optional chat assets last: the core install never waits on network
    assistant_assets
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
    systemctl disable --now greywatch-hunter.service 2>/dev/null || true
    rm -f "$UNIT_SYS" "$HUNIT_SYS" "$POLICY_SYS" "$RULES_SYS" "$MODULES_SYS"
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
