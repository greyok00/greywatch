from __future__ import annotations

import errno
import json
import os
import stat as _stat

GREEN, YELLOW, RED, OFF = "GREEN", "YELLOW", "RED", "OFF"
UNKNOWN = "UNKNOWN"      # the probe could not answer — never guess
NO_UNIT = "no-unit"      # = NOT INSTALLED (the unit never existed)

_RANK = {GREEN: 0, UNKNOWN: 1, YELLOW: 1, RED: 2}


def worst_from(states, rank=_RANK):
    return max(states, key=lambda s: rank.get(s, 2))

ACTIVE, INACTIVE, FAILED, NO_UNIT, UNKNOWN_UNIT = \
    "active", "inactive", "failed", "no-unit", "unknown"


def classify(unit_state: str, log_state: str,
             expects_unit: bool, needs_log: bool) -> str:
    if expects_unit and unit_state == UNKNOWN_UNIT:
        return UNKNOWN         # the probe failed — do not invent a verdict
    if expects_unit and unit_state == NO_UNIT:
        return YELLOW          # no unit ANYWHERE → the tool isn't installed
    if expects_unit and unit_state == FAILED:
        return RED
    if needs_log and log_state == "unreadable":
        return YELLOW          # root-readable only: the root daemon reads it
    if needs_log and log_state == "missing":
        if expects_unit and unit_state == INACTIVE:
            return RED         # dead unit AND nothing written
        return YELLOW
    if expects_unit and unit_state == INACTIVE:
        return RED             # installed, not running
    return GREEN


def log_state_of(path: str) -> str:
    if str(path).startswith("journal:"):
        return "ok"
    try:
        if not os.path.exists(path):
            return "missing"
        with open(path, "rb"):
            return "ok"
    except (OSError, PermissionError):
        return "unreadable"


def snapshot(registry: list, unit_checker) -> dict:
    tools = {}
    for t in registry:
        expects = t.get("unit") is not None
        t["_installed_hint"] = t.get("installed", True)
        unit_state = unit_checker(t) if expects else NO_UNIT
        log_states = [log_state_of(p) for p in t.get("logs", [])]
        if expects and log_states:
            state = worst_from(classify(unit_state, ls, True, True)
                               for ls in log_states)
        elif expects:                       # unit-managed, journal-based tool
            state = classify(unit_state, "ok", True, False)
        elif log_states:
            state = worst_from(classify(unit_state, ls, False, True)
                               for ls in log_states)
        else:
            state = GREEN
        tools[t["name"]] = {
            "label": t["label"], "state": state, "last_event": None,
            "unit_state": unit_state,
            "installed": t.get("_installed", None),
        }
    return {"updated": _utc_now(), "tools": tools}


def _utc_now():
    import datetime
    return datetime.datetime.now(datetime.timezone.utc) \
        .isoformat(timespec="seconds")


def _stage_for(path: str) -> str:
    """Name of a root-controlled staging directory inside path's parent.

    The state directory is shared with the desktop group (GW-01), so a
    fixed "<name>.tmp" beside the real file is a name a group member can
    pre-plant — as a symlink (root then follows it and truncates the
    target) or as content a later os.replace would promote. Temp files
    therefore live in ".root-tmp", created 0700 and owned by the
    effective (root) user and verified on EVERY call: a group member can
    rename the whole dir away as a denial-of-service but can never
    create, read, or substitute an entry inside it. Refusal is loud
    (OSError) — callers surface it via the failure counters; nothing
    silently bypasses the staging.
    """
    d = os.path.join(os.path.dirname(os.path.abspath(path)), ".root-tmp")
    try:
        st = os.lstat(d)
    except FileNotFoundError:
        os.mkdir(d, 0o700)
        st = os.lstat(d)
    if not (_stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid()
            and (st.st_mode & 0o077) == 0):
        raise OSError(errno.EPERM,
                      f"refusing {d}: not a private dir owned by "
                      f"uid {os.geteuid()}")
    return d


def atomic_replace(path: str, data: str, gid: int | None = None) -> None:
    """Write data to a root-owned file via a staging dir, the open fd,
    and one atomic rename — never following anything a group member
    planted. Permissions are applied to the INODE through the open fd
    (fchown/fchmod), so there is no path-based chmod left to follow.
    Raises OSError on any refusal; callers must surface it."""
    target = 0o640 if gid is not None else 0o600
    stage = _stage_for(path)
    tmp = os.path.join(stage, os.path.basename(path) + ".new")
    fd = -1
    for _ in range(2):          # a stale ".new" is ours from a crash: ours to clear
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                              | os.O_NOFOLLOW, 0o600)
            break
        except FileExistsError:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass
        except OSError:
            raise
    if fd < 0:
        raise OSError(errno.EEXIST, f"could not stage {tmp}")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(data)
            f.flush()
            if gid is not None:
                try:
                    os.fchown(f.fileno(), -1, gid)
                except OSError:
                    target = 0o600
            try:
                os.fchmod(f.fileno(), target)
            except OSError:
                pass
            os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def append_checked(path: str, text: str, create_mode: int = 0o600,
                   gid: int | None = None) -> None:
    """Append to a root-owned event/log file in the shared state dir.

    GW-01: the desktop group can plant a SYMLINK named events.jsonl (or
    any other output) before the daemon's first write — a plain open("a")
    would follow it and have root append into a foreign file. Here the
    file is created exclusively (O_EXCL|O_NOFOLLOW) if missing, and the
    inode ACTUALLY OPENED is verified via fstat: refused (OSError) unless
    it is a regular file owned by the effective (root) uid and not
    group/world-writable. Refusal must be surfaced by the caller."""
    try:
        os.close(os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT
                              | os.O_EXCL | os.O_NOFOLLOW, create_mode))
    except FileExistsError:
        pass
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
    st = os.fstat(fd)
    if not (_stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid()
            and (st.st_mode & 0o022) == 0):
        os.close(fd)
        raise OSError(errno.EPERM,
                      f"refusing append to {path}: not a private "
                      f"root-owned regular file")
    if gid is not None:
        # Same contract as status.json: root owns it, the desktop user's
        # group may READ it (0640), nobody may write it. Without this the
        # GUI — which runs as the desktop user — cannot read events.jsonl
        # and every security prompt silently disappears (2026-10-27).
        try:
            os.fchown(fd, -1, gid)
            os.fchmod(fd, 0o640)
        except OSError:
            pass
    with os.fdopen(fd, "a") as f:
        f.write(text)


def write_status(path: str, status: dict, gid: int | None = None) -> None:
    # The status file carries the recent-event digest, so it must NOT be
    # world-readable. It is written 0640 and, when the desktop user's
    # group is known, that group is set on it — the dashboard stays
    # readable for the intended user, closed to unrelated accounts.
    # Without a group (unknown UI user): 0600. The write itself goes
    # through the private staging dir + fd-based perms + one atomic
    # rename (atomic_replace) so a group member cannot redirect it.
    atomic_replace(path, json.dumps(status, separators=(",", ":")), gid=gid)


def load_status(path: str) -> dict:
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"updated": None, "tools": {}}
