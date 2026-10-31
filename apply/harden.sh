#!/bin/bash
set -uo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd) || exit 2
REPO_DIR=$(cd -- "$SCRIPT_DIR/.." && pwd) || exit 2
DATA_DIR="${GREYWATCH_DATA_DIR:-$REPO_DIR/data}"
BACKUP_ROOT="$DATA_DIR/backups/harden"
JOURNAL_PATH="$DATA_DIR/hardening-journal.jsonl"
SYSCTL_CONF="${GREYWATCH_TEST_SYSCTL_CONF:-/etc/sysctl.d/99-greywatch-hardening.conf}"

usage() {
    echo "usage: harden.sh apply <plan.json>|<changeset.json> | undo <journal-id> <journal-path> | verify <journal-id> <journal-path> | plan <plan.json>" >&2
    exit 64
}

[ $# -ge 1 ] || usage
MODE=$1
case "$MODE" in
    apply|--apply) [ $# -eq 2 ] || usage ;;
    undo|--undo)   [ $# -eq 3 ] || usage ;;
    verify|--verify) [ $# -eq 3 ] || usage ;;
    plan)          [ $# -eq 2 ] || usage ;;
    *)
        if [[ "$MODE" =~ ^(--)?[A-Za-z-]+$ ]]; then
            echo "unknown verb: $MODE (not in the allowlist)" >&2
        else
            echo "unknown verb (not in the allowlist)" >&2
        fi
        exit 2
        ;;
esac
MODE=${MODE#--}

TD=$(mktemp -d "${TMPDIR:-/tmp}/harden.XXXXXX") || exit 2
trap 'rm -rf -- "$TD"' EXIT


get() {
    python3 - "$1" "$2" <<'PY'
import json, sys
try:
    e = json.load(open(sys.argv[1], encoding="utf-8"))
except (OSError, ValueError):
    sys.exit(2)
v = e.get(sys.argv[2], "")
if isinstance(v, bool):
    v = "True" if v else "False"
elif not isinstance(v, str):
    v = ""
print(v)
PY
}

put_text() {
    python3 - "$1" "$2" "$3" <<'PY'
import json, sys
try:
    e = json.load(open(sys.argv[1], encoding="utf-8"))
except (OSError, ValueError):
    sys.exit(2)
v = e.get(sys.argv[2], "")
if not isinstance(v, str):
    sys.exit(2)
with open(sys.argv[3], "w", encoding="utf-8") as fh:
    fh.write(v)
PY
}

split_entries() {
    python3 - "$1" "$2" <<'PY'
import json, sys, os
try:
    plan = json.load(open(sys.argv[1], encoding="utf-8"))
except (OSError, ValueError):
    sys.exit(2)
entries = plan.get("entries", []) if isinstance(plan, dict) else plan
if not isinstance(entries, list):
    sys.exit(2)
for i, e in enumerate(entries):
    if not isinstance(e, dict):
        sys.exit(2)
    with open(os.path.join(sys.argv[2], "e.%03d.json" % i), "w",
              encoding="utf-8") as fh:
        fh.write(json.dumps(e))
PY
}

sniff_shape() {
    python3 - "$1" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1], encoding="utf-8"))
except (OSError, ValueError):
    sys.exit(0)
if isinstance(d, dict):
    if "journal_id" in d and "changes" in d:
        print("changeset")
    elif "entries" in d and isinstance(d.get("entries"), list):
        print("plan")
    else:
        print("none")
elif isinstance(d, list):
    print("bare")
PY
}

changeset_translate() {
    python3 - "$1" "$2" "$3" "$4" "$5" <<'PY'
import json, os, re, sys
cfile, eout, rbf, errf, datadir = sys.argv[1:6]
CS_ACTIONS = ("apply", "verify", "rollback")
ID_RE = re.compile(r"^[A-Za-z0-9._-]+$")
JID_RE = re.compile(r"^[0-9]{8}-[0-9]{6}$")
FPATH_RE = re.compile(
    r"^(data/harden/journal/[0-9]{8}-[0-9]{6}/[A-Za-z0-9._-]+\.json"
    r"|/(?:[A-Za-z0-9._-]+/)*harden/journal/[0-9]{8}-[0-9]{6}/"
    r"[A-Za-z0-9._-]+\.json)$")
CS_KEYS = {"control_id", "action", "backup_path"}


def fail(msg):
    with open(errf, "w", encoding="utf-8") as fh:
        fh.write(msg + "\n")
    sys.exit(2)


try:
    cs = json.load(open(cfile, encoding="utf-8"))
except (OSError, ValueError):
    fail("CHANGES-BAD-JSON")
if not isinstance(cs, dict) or "journal_id" not in cs or "changes" not in cs:
    fail("CHANGES-SHAPE")
if not isinstance(cs["journal_id"], str) or not JID_RE.fullmatch(cs["journal_id"]):
    fail("CHANGES-BAD-JOURNAL-ID")
if cs.get("version") != 1:
    fail("CHANGES-BAD-VERSION")
changes = cs["changes"]
if not isinstance(changes, list) or not all(isinstance(c, dict) for c in changes):
    fail("CHANGES-BAD-CHANGES")
journal_root = os.path.join(os.path.abspath(datadir), "harden", "journal")
pass_dir = os.path.join(journal_root, cs["journal_id"])


def resolve_bp(cid, action, bpath):
    """Shape-gate then scope-gate one backup_path, and return the
    RESOLVED absolute path every later open uses."""
    if not isinstance(bpath, str) or isinstance(bpath, bool):
        fail("CHANGES-BACKUP-PATH %s" % cid)
    if ".." in bpath.replace("\\", "/").split("/"):
        fail("CHANGES-BACKUP-PATH-TRAVERSAL %s" % cid)
    if not FPATH_RE.fullmatch(bpath):
        fail("CHANGES-BACKUP-PATH %s" % cid)
    cand = bpath if bpath.startswith("/") \
        else os.path.join(os.path.dirname(os.path.abspath(datadir)), bpath)
    real = os.path.realpath(cand)
    parent = os.path.dirname(real)
    if action == "rollback":
        tgt_ok = parent.startswith(os.path.realpath(journal_root) + os.sep) \
            and JID_RE.fullmatch(os.path.basename(parent) or "")
        if not tgt_ok:
            fail("CHANGES-ROLLBACK-SCOPE %s" % cid)
        tjr = os.path.realpath(os.path.join(parent, "journal.jsonl"))
        if os.path.dirname(tjr) != parent:
            fail("CHANGES-ROLLBACK-SCOPE %s" % cid)
        return real, tjr
    if parent != os.path.realpath(pass_dir):
        fail("CHANGES-BACKUP-PATH-SCOPE %s" % cid)
    return real, None


seen: set = set()
applies: list = []
verifies: list = []
rollbacks: list = []
for ch in changes:
    if set(ch) - CS_KEYS:
        fail("CHANGES-UNKNOWN-KEY")
    cid = ch.get("control_id")
    if not isinstance(cid, str) or not ID_RE.fullmatch(cid):
        fail("CHANGES-BAD-CONTROL-ID")
    if cid in seen:
        fail("CHANGES-DUP-ID %s" % cid)
    seen.add(cid)
    action = ch.get("action")
    if action not in CS_ACTIONS:
        fail("CHANGES-BAD-ACTION %s" % cid)
    frag_path, tgt_journal = resolve_bp(cid, action, ch.get("backup_path"))
    try:
        frag = json.load(open(frag_path, encoding="utf-8"))
    except (OSError, ValueError):
        frag = None
    if not isinstance(frag, dict) or not isinstance(frag.get("entries"), list):
        fail("CHANGES-BAD-FRAGMENT %s" % cid)
    for fe in frag["entries"]:
        if not isinstance(fe, dict) or not isinstance(fe.get("id"), str) \
                or not ID_RE.fullmatch(fe.get("id", "")):
            fail("CHANGES-BAD-FRAGMENT-ENTRY %s" % cid)
        if action == "apply":
            applies.append(fe)
        elif action == "verify":
            ve = {"id": fe["id"], "verb": "sh", "cmd": "true",
                  "probe": fe.get("probe", "")}
            if fe.get("probe_invert") is True:
                ve["probe_invert"] = True
            verifies.append(ve)
    if action == "rollback":
        rollbacks.append("%s\t%s" % (cid, tgt_journal))
built = applies + verifies
if rbf is not None and rollbacks:
    with open(rbf, "w", encoding="utf-8") as fh:
        fh.writelines(r + "\n" for r in rollbacks)
for i, e in enumerate(built):
    with open(os.path.join(eout, "e.%03d.json" % i), "w", encoding="utf-8") as fh:
        fh.write(json.dumps(e))
print(cs["journal_id"])
PY
}

sysctl_set() {
    python3 - "$1" "$2" "$SYSCTL_CONF" <<'PY'
import sys
key, val, path = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    lines = open(path, encoding="utf-8").read().splitlines()
except OSError:
    lines = []
out = [l for l in lines if not l.strip() or l.lstrip().startswith("#")
       or l.split("=", 1)[0].strip() != key]
out.append("%s = %s" % (key, val))
with open(path, "w", encoding="utf-8") as fh:
    fh.write("\n".join(out) + "\n")
PY
}

ok_plain_text() {
    case "$1" in
        "") return 1 ;;
        *[![:print:]]*) return 1 ;;
    esac
    printf '%s' "$1" | grep -qE '[`|&;\\]' && return 1
    return 0
}

worse_rc() {
    case "$rc" in
        0) rc=$1 ;;
        2) case "$1" in 4|5) rc=$1 ;; esac ;;
        4) case "$1" in 5) rc=$1 ;; esac ;;
    esac
}

capture_before() {
    python3 - "$1" <<'PY'
import base64, pathlib, sys
p = pathlib.Path(sys.argv[1])
if not p.exists():
    sys.stdout.write("ABSENT\t%s\n" % p)
    sys.exit(0)
try:
    data = p.read_bytes()
except OSError:
    sys.exit(2)
sys.stdout.write(
    "B64\t%s\t%s\n" % (base64.b64encode(data).decode("ascii"), p))
PY
}

journal_write() {
    python3 - "$JOURNAL_PATH" "$TD/journal.tsv" "$1" "$2" <<'PY'
import json, sys
from datetime import datetime, timezone
jpath, tsv, efile, jid = sys.argv[1:5]
try:
    entry = json.load(open(efile, encoding="utf-8"))
except (OSError, ValueError):
    sys.exit(2)
try:
    tsv_text = open(tsv, encoding="utf-8").read()
except OSError:
    tsv_text = ""
before = {}
for line in tsv_text.splitlines():
    parts = line.split("\t")
    kind = parts[0] if parts else ""
    if kind == "ABSENT" and len(parts) == 2:
        before[parts[1]] = {"absent": True}
    elif kind == "B64" and len(parts) == 3:
        before[parts[2]] = {"blob": parts[1]}
    elif kind == "STATE" and len(parts) == 4:
        before[parts[1]] = {"was-enabled": parts[2],
                            "was-active": parts[3]}
if not before:
    sys.exit(2)
record = {
    "id": jid,
    "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "before": before,
    "plan": [entry],
}
try:
    with open(jpath, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")
except OSError:
    sys.exit(2)
PY
}


ok_id() {
    case "$1" in
        *[!A-Za-z0-9._-]*) return 1 ;;
        "") return 1 ;;
        *) return 0 ;;
    esac
}

ok_sysctl_key() {
    case "$1" in
        *[!A-Za-z0-9._/-]*) return 1 ;;
        "") return 1 ;;
        *) return 0 ;;
    esac
}

backup_of() {
    local bdir="$BACKUP_ROOT/$1" bfile
    bfile=$(basename -- "$2")
    mkdir -p -- "$bdir" || return 1
    if [ -f "$2" ]; then
        cp -- "$2" "$bdir/$bfile.bak" || return 1
    else
        : > "$bdir/$bfile.absent" || return 1
    fi
}

rollback_of() {
    local efile=$1 verb id path bdir bfile unit ret=0
    verb=$(get "$efile" verb)
    id=$(get "$efile" id)
    [ -n "$id" ] || { echo "ROLLBACK-FAILED <unprintable-id>" >&2; return 1; }
    bdir="$BACKUP_ROOT/$id"
    case "$verb" in
        unit-install)
            path=$(get "$efile" path)
            if [ -z "$path" ]; then
                echo "ROLLBACK-FAILED $id" >&2
                return 1
            fi
            bfile="$bdir/$(basename -- "$path")"
            if [ -f "$bfile.bak" ]; then
                cp -- "$bfile.bak" "$path" || ret=1
            elif [ -f "$bfile.absent" ]; then
                rm -f -- "$path" || ret=1
            else
                ret=1
            fi
            systemctl daemon-reload 2>/dev/null || ret=1
            systemctl restart "$(basename -- "$path")" 2>/dev/null || ret=1
            ;;
        sysctl-set)
            snapped=0
            for snapdir in "$bdir" "$BACKUP_ROOT/_sysctl-snapshot"; do
                if [ -f "$snapdir/99-greywatch-hardening.conf.bak" ]; then
                    cp -- "$snapdir/99-greywatch-hardening.conf.bak" \
                        "$SYSCTL_CONF" || ret=1
                    snapped=1
                    break
                elif [ -f "$snapdir/99-greywatch-hardening.conf.absent" ]; then
                    rm -f -- "$SYSCTL_CONF" || ret=1
                    snapped=1
                    break
                fi
            done
            [ "$snapped" -eq 1 ] || ret=1     # nothing to restore from
            sysctl --system 2>/dev/null || ret=1
            ;;
        service-off)
            unit=$(get "$efile" unit)
            if [ -z "$unit" ]; then
                echo "ROLLBACK-FAILED $id" >&2
                return 1
            fi
            if [ -f "$bdir/unit.was-enabled" ] \
                && [ "$(cat -- "$bdir/unit.was-enabled")" = "enabled" ]; then
                systemctl enable -- "$unit" 2>/dev/null || ret=1
            fi
            if [ -f "$bdir/unit.was-active" ] \
                && [ "$(cat -- "$bdir/unit.was-active")" = "active" ]; then
                systemctl start -- "$unit" 2>/dev/null || ret=1
            fi
            ;;
        *) : ;;
    esac
    if [ "$ret" -ne 0 ]; then
        echo "ROLLBACK-FAILED $id" >&2
        return 1
    fi
    return 0
}

run_probe() {
    local probe probe_rc
    probe=$(get "$1" probe)
    [ -n "$probe" ] || return 0
    bash -c "$probe" >/dev/null 2>&1
    probe_rc=$?
    if [ "$(get "$1" probe_invert)" = "True" ]; then
        [ "$probe_rc" -eq 0 ] && probe_rc=1 || probe_rc=0
    fi
    return "$probe_rc"
}


rc=0
if [ "$MODE" = "apply" ]; then
    planfile=$2
    [ -r "$planfile" ] || { echo "plan not readable: $planfile" >&2; exit 2; }
    shape=$(sniff_shape "$planfile")
    case "$shape" in
        changeset)
            csjid=$(changeset_translate "$planfile" "$TD" \
                "$TD/rollback.list" "$TD/cs.err" "$DATA_DIR") \
                || { cserr=$(cat -- "$TD/cs.err" 2>/dev/null)
                     case "$cserr" in
                         ""|*[![:print:]]*)
                             echo "changeset refused (unprintable error)" >&2 ;;
                         *) echo "$cserr" >&2 ;;
                     esac
                     exit 2 ; }
            BACKUP_ROOT="$DATA_DIR/harden/journal/$csjid/backups"
            JOURNAL_PATH="$DATA_DIR/harden/journal/$csjid/journal.jsonl"
            mkdir -p -- "$BACKUP_ROOT" \
                "$(dirname -- "$JOURNAL_PATH")" || exit 2
            ;;
        *)          # plain plan JSON (or a bare entries list): unchanged flow
            if [ "$shape" = "none" ]; then
                echo "CHANGES-SHAPE (neither a plan nor a changeset)" >&2
                exit 2
            fi
            split_entries "$planfile" "$TD" || { echo "bad plan json" >&2; exit 2; }
            ;;
    esac
    mkdir -p -- "$BACKUP_ROOT" || exit 2

    shopt -s nullglob
    efiles=("$TD"/e.*.json)
    shopt -u nullglob
    if [ "${#efiles[@]}" -eq 0 ] && [ ! -s "$TD/rollback.list" ]; then
        echo "CHANGES-SHAPE (a pass carries no changes)" >&2
        exit 2
    fi
    for efile in "${efiles[@]}"; do
        id=$(get "$efile" id)
        verb=$(get "$efile" verb)
        if ! ok_id "$id"; then
            echo "BAD-ID <unprintable>" >&2
            rc=2
            printf '%s\n' "$(basename -- "$efile")" >> "$TD/skip.list"
            continue
        fi
        case "$verb" in
            sh)
                step_rc=0
                cmd=$(get "$efile" cmd)
                if [ -z "$cmd" ]; then
                    echo "BAD-CMD $id" >&2
                    rc=2
                    printf '%s\n' "$(basename -- "$efile")" >> "$TD/skip.list"
                    continue
                fi
                bash -c "$cmd" >/dev/null 2>&1 || step_rc=$?
                echo "APPLY $id $step_rc"
                [ "$step_rc" -eq 0 ] || rc=2
                ;;
            unit-install)
                path=$(get "$efile" path)
                if ! put_text "$efile" text "$TD/unit.txt" || [ -z "$path" ]; then
                    echo "BAD-UNIT-INSTALL $id" >&2
                    rc=2
                    printf '%s\n' "$(basename -- "$efile")" >> "$TD/skip.list"
                    continue
                fi
                step_rc=0
                backup_of "$id" "$path" || {
                    echo "BACKUP-FAILED $id" >&2
                    rc=2
                    printf '%s\n' "$(basename -- "$efile")" >> "$TD/skip.list"
                    continue
                }
                : > "$TD/journal.tsv"
                capture_before "$path" >> "$TD/journal.tsv" \
                    || { echo "BACKUP-FAILED $id" >&2; rc=2
                         printf '%s\n' "$(basename -- "$efile")" >> "$TD/skip.list"
                         continue; }
                journal_write "$efile" "$id" \
                    || { echo "BACKUP-FAILED $id" >&2; rc=2
                         printf '%s\n' "$(basename -- "$efile")" >> "$TD/skip.list"
                         continue; }
                install -m 0644 -- "$TD/unit.txt" "$path" || step_rc=$?
                systemctl daemon-reload || step_rc=$?
                systemctl restart "$(basename -- "$path")" || step_rc=$?
                echo "APPLY $id $step_rc"
                [ "$step_rc" -eq 0 ] || rc=2
                ;;
            sysctl-set)
                key=$(get "$efile" key)
                val=$(get "$efile" value)
                if ! ok_sysctl_key "$key" || ! ok_plain_text "$val"; then
                    echo "BAD-SYSCTL $id" >&2
                    rc=2
                    printf '%s\n' "$(basename -- "$efile")" >> "$TD/skip.list"
                    continue
                fi
                step_rc=0
                if [ -f "$TD/sysctl.snapshot" ]; then
                    :
                else
                    backup_of "_sysctl-snapshot" "$SYSCTL_CONF" \
                        || { echo "BACKUP-FAILED $id" >&2; rc=2
                             printf '%s\n' "$(basename -- "$efile")" >> "$TD/skip.list"
                             continue; }
                    : > "$TD/sysctl.snapshot" \
                        || { echo "BACKUP-FAILED $id" >&2; rc=2
                             printf '%s\n' "$(basename -- "$efile")" >> "$TD/skip.list"
                             continue; }
                fi
                : > "$TD/journal.tsv"
                capture_before "$SYSCTL_CONF" >> "$TD/journal.tsv" \
                    || { echo "BACKUP-FAILED $id" >&2; rc=2
                         printf '%s\n' "$(basename -- "$efile")" >> "$TD/skip.list"
                         continue; }
                journal_write "$efile" "$id" \
                    || { echo "BACKUP-FAILED $id" >&2; rc=2
                         printf '%s\n' "$(basename -- "$efile")" >> "$TD/skip.list"
                         continue; }
                sysctl_set "$key" "$val" || step_rc=$?
                sysctl --system >/dev/null 2>&1 || step_rc=$?
                echo "APPLY $id $step_rc"
                [ "$step_rc" -eq 0 ] || rc=2
                ;;
            service-off)
                unit=$(get "$efile" unit)
                if [ -z "$unit" ] || ! ok_plain_text "$unit"; then
                    echo "BAD-SERVICE-OFF $id" >&2
                    rc=2
                    printf '%s\n' "$(basename -- "$efile")" >> "$TD/skip.list"
                    continue
                fi
                step_rc=0
                bdir="$BACKUP_ROOT/$id"
                mkfail() { echo "BACKUP-FAILED $id" >&2; rc=2
                           printf '%s\n' "$(basename -- "$efile")" >> "$TD/skip.list"; }
                mkdir -p -- "$bdir" || { mkfail; continue; }
                state_en=$(systemctl is-enabled -- "$unit" 2>/dev/null || true)
                state_ac=$(systemctl is-active -- "$unit" 2>/dev/null || true)
                if ! printf '%s\n' "${state_en:-not-found}" \
                        > "$bdir/unit.was-enabled" \
                    || ! printf '%s\n' "${state_ac:-not-found}" \
                        > "$bdir/unit.was-active"; then
                    mkfail
                    continue
                fi
                : > "$TD/journal.tsv"
                printf 'STATE\t%s\t%s\t%s\n' "$unit" \
                    "${state_en:-not-found}" "${state_ac:-not-found}" \
                    >> "$TD/journal.tsv"
                journal_write "$efile" "$id" || { mkfail; continue; }
                systemctl disable --now -- "$unit" 2>/dev/null
                step_rc=$?
                echo "APPLY $id $step_rc"
                [ "$step_rc" -eq 0 ] || rc=2
                ;;
            pkg-upgrade)
                # upgrade, never full-upgrade: nothing is removed, and
                # --force-confold keeps local config files in place.
                env DEBIAN_FRONTEND=noninteractive \
                    apt-get -y -o Dpkg::Options::=--force-confold \
                    upgrade >/dev/null 2>&1
                step_rc=$?
                echo "APPLY $id $step_rc"
                [ "$step_rc" -eq 0 ] || rc=2
                ;;
            pkg-install)
                pkg=$(get "$efile" package)
                if [[ ! "$pkg" =~ ^[a-z0-9.+-]+$ ]]; then
                    echo "BAD-PKG $id" >&2
                    rc=2
                    printf '%s\n' "$(basename -- "$efile")" >> "$TD/skip.list"
                    continue
                fi
                env DEBIAN_FRONTEND=noninteractive \
                    apt-get -y install -- "$pkg" >/dev/null 2>&1
                step_rc=$?
                echo "APPLY $id $step_rc"
                [ "$step_rc" -eq 0 ] || rc=2
                ;;
            pending-restarts)
                REBOOT_FILE="${GREYWATCH_TEST_REBOOT_REQUIRED:-/var/run/reboot-required}"
                REBOOT_PKGS="${REBOOT_FILE}.pkgs"
                python3 - "$REBOOT_FILE" "$REBOOT_PKGS" <<'PY'
import json, os, sys
reboot, pkgs = sys.argv[1], sys.argv[2]
doc = {"reboot_required": os.path.exists(reboot), "packages": [],
       "services": [], "needrestart": False}
if os.path.exists(pkgs):
    try:
        doc["packages"] = [ln.strip() for ln in
                           open(pkgs, encoding="utf-8") if ln.strip()]
    except OSError:
        pass
print(json.dumps(doc, separators=(",", ":")))
PY
                step_rc=$?
                echo "APPLY $id $step_rc"
                ;;
            restart-units)
                units=$(get "$efile" units)
                if [ -z "$units" ]; then
                    echo "BAD-UNITS $id" >&2
                    rc=2
                    printf '%s\n' "$(basename -- "$efile")" >> "$TD/skip.list"
                    continue
                fi
                step_rc=0
                IFS=',' read -r -a ulist <<< "$units"
                for u in "${ulist[@]}"; do
                    if [[ ! "$u" =~ ^[A-Za-z0-9@._-]+$ ]]; then
                        echo "BAD-UNITS $id" >&2
                        step_rc=2
                        break
                    fi
                done
                if [ "$step_rc" -ne 0 ]; then
                    rc=2
                    printf '%s\n' "$(basename -- "$efile")" >> "$TD/skip.list"
                    continue
                fi
                for u in "${ulist[@]}"; do
                    systemctl restart -- "$u" >/dev/null 2>&1 || step_rc=$?
                done
                echo "APPLY $id $step_rc"
                [ "$step_rc" -eq 0 ] || rc=2
                ;;
            *)
                if [[ "$verb" =~ ^[a-z-]+$ ]]; then
                    echo "verb not allowed: $verb" >&2
                else
                    echo "verb not allowed (unprintable)" >&2
                fi
                rc=2
                printf '%s\n' "$(basename -- "$efile")" >> "$TD/skip.list"
                continue
                ;;
        esac
    done

    for efile in "${efiles[@]}"; do
        grep -qxF "$(basename -- "$efile")" "$TD/skip.list" 2>/dev/null && continue
        id=$(get "$efile" id)
        verb=$(get "$efile" verb)
        case "$verb" in
            sh|unit-install|sysctl-set|service-off|pkg-upgrade|pkg-install|pending-restarts|restart-units) ;;
            *) continue ;;
        esac
        ok_id "$id" || continue
        if [ -z "$(get "$efile" probe)" ]; then
            echo "VERBIFY $id none"
            continue
        fi
        if run_probe "$efile"; then
            echo "VERBIFY $id 0"
        else
            probe_rc=$?
            echo "VERBIFY $id $probe_rc"
            case "$verb" in
                sh|pkg-upgrade|pkg-install|pending-restarts|restart-units)
                    echo "ROLLBACK-SKIP $id" >&2
                    worse_rc 4
                    ;;
                *)
                    if rollback_of "$efile"; then
                        echo "ROLLBACK $id"
                        worse_rc 4
                    else
                        worse_rc 5
                    fi
                    ;;
            esac
        fi
    done

    if [ -s "$TD/rollback.list" ]; then
        while IFS=$'\t' read -r rjid rjpath; do
            [ -n "$rjid" ] || continue
            echo "CHANGES-ROLLBACK $rjid"
            rbout=$(bash -- "$0" undo "$rjid" "$rjpath" 2>&1)
            rbrc=$?
            printf '%s\n' "$rbout"
            case "$rbrc" in
                0|3) : ;;
                *) worse_rc 2 ;;
            esac
        done < "$TD/rollback.list"
    fi
fi


if [ "$MODE" = "plan" ]; then
    planfile=$2
    [ -r "$planfile" ] || { echo "plan not readable: $planfile" >&2; exit 2; }
    split_entries "$planfile" "$TD" || { echo "bad plan json" >&2; exit 2; }
    cat -- "$planfile"
    echo
fi


if [ "$MODE" = "undo" ] || [ "$MODE" = "verify" ]; then
    jid=$2
    jpath=$3
    ! ok_id "$jid" && { echo "bad journal id" >&2; exit 2; }
    [ -r "$jpath" ] || { echo "journal not readable: $jpath" >&2; exit 2; }

    python3 - "$jid" "$jpath" > "$TD/undo.tsv" <<'PY'
import base64, json, sys
jid, jpath = sys.argv[1], sys.argv[2]
try:
    raw = open(jpath, encoding="utf-8").read()
except OSError:
    sys.exit(2)
entry = None
for line in raw.splitlines():
    line = line.strip()
    if not line:
        continue
    try:
        rec = json.loads(line)
    except ValueError:
        continue
    if isinstance(rec, dict) and rec.get("id") == jid:
        entry = rec
if not isinstance(entry, dict):
    sys.exit(2)
before = entry.get("before") or {}
vals = before.get(jid, before)
if not isinstance(vals, dict):
    sys.exit(2)
for path, val in vals.items():
    if path == "blob" or "\t" in path or "\n" in path or not path:
        continue
    if isinstance(val, dict):
        if "blob" in val:
            payload = val["blob"]
            try:
                data = base64.b64decode(payload)
            except (ValueError, TypeError):
                continue
            enc = base64.b64encode(data).decode("ascii")
            sys.stdout.write("B64\t%s\t%s\n" % (enc, path))
        elif val.get("absent") is True:
            sys.stdout.write("ABSENT\t%s\n" % path)
        elif "was-enabled" in val or "was-active" in val:
            en, ac = val.get("was-enabled") or "", val.get("was-active") or ""
            if not isinstance(en, str) or not isinstance(ac, str) or "/" in path \
                    or "\t" in en + ac or "\n" in en + ac:
                continue
            sys.stdout.write("STATE\t%s\t%s\t%s\n" % (path, en, ac))
        else:
            text = val.get("text", "")
            if not isinstance(text, str):
                continue
            enc = base64.b64encode(text.encode("utf-8")).decode("ascii")
            sys.stdout.write("B64\t%s\t%s\n" % (enc, path))
    elif isinstance(val, str):
        enc = base64.b64encode(val.encode("utf-8")).decode("ascii")
        sys.stdout.write("B64\t%s\t%s\n" % (enc, path))
    elif isinstance(val, bytes):
        enc = base64.b64encode(val).decode("ascii")
        sys.stdout.write("B64\t%s\t%s\n" % (enc, path))
PY
    [ $? -eq 0 ] || { echo "journal id not found: $jid" >&2; exit 2; }

    if [ "$MODE" = "undo" ]; then
    n=0
    while IFS=$'\t' read -r kind a b c; do
        case "$kind" in
            B64)
                [ -n "$a" ] || continue
                mkdir -p -- "$(dirname -- "$b")" 2>/dev/null
                python3 - "$a" "$b" <<'PY'
import base64, sys
try:
    data = base64.b64decode(sys.argv[1])
    with open(sys.argv[2], "wb") as fh:
        fh.write(data)
except (ValueError, TypeError, OSError):
    sys.exit(1)
PY
                if [ $? -eq 0 ]; then
                    echo "RESTORE $jid $b"
                    n=$((n + 1))
                else
                    echo "RESTORE-FAILED $jid $b" >&2
                    [ "$rc" -eq 0 ] && rc=2
                fi
                case "$b" in
                    *.service) systemctl daemon-reload 2>/dev/null
                               systemctl restart "$(basename -- "$b")" 2>/dev/null ;;
                    */sysctl.d/*) sysctl --system 2>/dev/null ;;
                esac
                ;;
            ABSENT)
                rm -f -- "$a" 2>/dev/null && {
                    echo "RESTORE-ABSENT $jid $a"
                    n=$((n + 1))
                } || { echo "RESTORE-FAILED $jid $a" >&2
                       [ "$rc" -eq 0 ] && rc=2; }
                ;;
            STATE)
                if [ "$b" = "enabled" ]; then
                    systemctl enable -- "$a" 2>/dev/null || true
                fi
                if [ "$c" = "active" ]; then
                    systemctl start -- "$a" 2>/dev/null || true
                fi
                echo "RESTORE-UNIT $jid $a"
                n=$((n + 1))
                ;;
            *) continue ;;
        esac
    done < "$TD/undo.tsv"
    [ "$n" -gt 0 ] || { echo "no before-values for id: $jid" >&2; exit 2; }
    fi    # undo-only restore loop; verify mode skips straight to probing

    split_journal_plan() {
        python3 - "$jpath" "$jid" "$TD" <<'PY'
import json, sys, os
jpath, jid, outdir = sys.argv[1], sys.argv[2], sys.argv[3]
for line in open(jpath, encoding="utf-8").read().splitlines():
    line = line.strip()
    if not line:
        continue
    try:
        rec = json.loads(line)
    except ValueError:
        continue
    if not (isinstance(rec, dict) and rec.get("id") == jid):
        continue
    plan = rec.get("plan") or []
    if isinstance(plan, dict):
        plan = plan.get("entries") or []
    for i, e in enumerate(plan):
        if isinstance(e, dict):
            with open(os.path.join(outdir, "e.%03d.json" % i), "w",
                      encoding="utf-8") as fh:
                fh.write(json.dumps(e))
PY
    }
    rm -f -- "$TD"/e.*.json 2>/dev/null
    if split_journal_plan; then
        for efile in "$TD"/e.*.json; do
            [ -f "$efile" ] || break
            id=$(get "$efile" id)
            [ -n "$(get "$efile" probe)" ] || { echo "VERBIFY $id none"; continue; }
            if run_probe "$efile"; then
                echo "VERBIFY $id 0"
            else
                probe_rc=$?
                echo "VERBIFY $id $probe_rc"
                [ "$rc" -eq 0 ] && rc=3
            fi
        done
    fi
fi

exit "$rc"
