"""appfw.enforce — the scope-mode enforcement core (design §6).

Known apps are enforced IN KERNEL: live /proc truth is rendered into
scope rules and swapped atomically. Unknown/unscoped connections hit
the catch rule (kernel DENY + LOG "GW-DENY"); the daemon tails the
kernel log, attributes the connection from the socket table, and runs
the SAME decide() chain (feeds → baseline → score → card). An owner's
card answer applies onward (design choice (b)).
"""
from __future__ import annotations

import pathlib
import re


class ScopeSnapshot:
    __slots__ = ("scopes", "unscoped_pids", "signature", "text",
                 "swapped", "swap_failed", "paths")

    def __init__(self, scopes: dict, unscoped_pids: list, signature: str):
        self.scopes = scopes
        self.unscoped_pids = unscoped_pids
        self.signature = signature


def _scope_basename(path: str) -> str:
    parts = [p for p in path.strip().split("/") if p]
    return parts[-1] if parts else ""


def _read_proc(pid: int) -> tuple[str, str, str] | None:
    """(exe, scope_basename, scope_full_path) for a pid; None when
    unreadable/kernel-thread. The FULL path rides along so the nft
    renderer derives the true `level N` depth (re-review C: the leaf
    alone renders level 1 — rules that never match). The cgroup line
    parse is appfw.scope's: one tokenizer for both consumers (M2)."""
    from appfw.scope import cgroup_scope
    base = pathlib.Path(f"/proc/{pid}")
    try:
        exe = pathlib.Path(str(base / "exe")).resolve().as_posix() \
            if (base / "exe").exists() else ""
        if not exe:
            return None                       # kernel thread or gone
        full = cgroup_scope(pid)
    except OSError:
        return None
    scope = _scope_basename(full)
    return (exe, scope, full)


def _scan_procs() -> dict[int, tuple[str, str, str]]:
    out: dict[int, tuple[str, str, str]] = {}
    for entry in pathlib.Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        row = _read_proc(int(entry.name))
        if row is not None:
            out[int(entry.name)] = row
    return out


def snapshot(app_rules: dict[str, str], trusted: set, baseline_apps: set,
             procs: dict | None = None) -> ScopeSnapshot:
    """Live process truth → per-scope verdicts. deny beats catch beats
    allow (fail-closed); a scope mixing unknown and known apps goes to
    the catch path wholesale. Unscoped processes are listable, never
    rule-able."""
    procs = _scan_procs() if procs is None else procs
    votes: dict[str, list[str | None]] = {}
    paths: dict[str, str] = {}         # leaf basename → live full path
    unscoped: list[int] = []
    for pid, (exe, scope, full) in procs.items():
        if not scope:
            unscoped.append(pid)
            continue
        paths.setdefault(scope, full)   # first-seen path; same leaf wins
        if exe in app_rules:
            verdict: str | None = app_rules[exe]
        elif exe in trusted or exe in baseline_apps:
            verdict = "allow"
        else:
            verdict = None                    # unknown: catch path
        votes.setdefault(scope, []).append(verdict)
    final: dict[str, str | None] = {}
    for scope, entries in votes.items():
        if "deny" in entries:
            final[scope] = "deny"
        elif all(v is None for v in entries):
            final[scope] = None
        elif "allow" in entries and None in entries:
            final[scope] = None               # mixed: fail closed
        else:
            final[scope] = "allow"
    scopes_only = {s: v for s, v in final.items()}
    signature = "|".join(f"{s}={v}" for s, v in sorted(scopes_only.items()))
    snap = ScopeSnapshot(scopes_only, unscoped, signature)
    snap.paths = paths
    return snap


from appfw import ruleset as ruleset      # noqa: E402 (render/swap shared)
from appfw.ruleset import render_ruleset  # noqa: E402
from appfw.ruleset import AppRule         # noqa: E402


def refresh(data_dir, app_rules: dict[str, str], trusted: set,
            baseline_apps: set, state=None, feed_sets=None,
            procs: dict | None = None, mode: str = "nfqueue") -> ScopeSnapshot:
    """One refresh: snapshot → render (known rules + feed IP sets) →
    swap ONLY when the engine runs nft-scope and the signature changed.
    With mode="nfqueue" (the default) this is a strict NO-OP: the
    NFQUEUE worker owns verdicts and a second table must never appear
    (review C2: dual tables = two verdict standards). Returns the
    snapshot with .text/.swapped attached for the caller's ledger."""
    snap = snapshot(app_rules, trusted, baseline_apps, procs=procs)
    if mode != "nft-scope":
        snap.text = ""
        snap.swapped = False
        snap.swap_failed = False
        return snap
    apps = [AppRule(scope=snap.paths.get(s, s), basename=s,
                    verdict=("allow" if v == "allow" else "deny"),
                    note=f"rebuild scope rule ({v})")
            for s, v in snap.scopes.items() if v is not None]
    if feed_sets is None:
        feed_sets = {}
    text = render_ruleset(apps, feed_sets, catch=True)
    snap.text = text
    previous = getattr(state, "signature", None) if state is not None else None
    # Refused-swap retry (carried minor 2): a swap the kernel refused
    # must not freeze the lane until process truth churns. "Already
    # rendered" keys on the signature AND the previous swap having
    # SUCCEEDED — a refused swap keeps wanting, so the next refresh
    # retries it.
    snap.swapped = (snap.signature != previous) or \
        bool(getattr(state, "swap_failed", False))
    if snap.swapped:
        if not ruleset.swap_ruleset(text):
            snap.swapped = False              # kernel said no; say so
            snap.swap_failed = True
        else:
            snap.swap_failed = False
    else:
        snap.swap_failed = False
    return snap


# ------------------------------------------------------- catch-path tail


_KERNEL_FIELDS = re.compile(
    r"\bDST=(?:(?P<dst>\d{1,3}(?:\.\d{1,3}){3})|(?P<dst6>[0-9a-fA-F:]{2,45}))"
    r"\b.*\bPROTO=(?P<proto>\w+)\b.*\bSPT=(?P<spt>\d+)\b.*\bDPT=(?P<dpt>\d+)\b",
    re.DOTALL)


class Conn:                                # local shape for the chain
    """appfw.base.Conn carries class-level defaults; a plain local twin
    avoids importing the engine's module graph from the tailer path."""

    def __init__(self, host="", dst_ip="", dst_port=0, proto="tcp",
                 pid=0, src_port=0, path="", app=""):
        self.host = host or dst_ip
        self.dst_ip = dst_ip
        self.dst_port = int(dst_port or 0)
        self.protocol = proto
        self.pid = int(pid or 0)
        self.src_port = int(src_port or 0)
        self.process_path = path
        self.process_args: list[str] = []
        self.app_name = app


def _socket_pid(src_port: int, dst_port: int) -> int:
    """/proc/net/tcp{,6} sweep: the socket with both ports → owner pid."""
    want = {(src_port, dst_port)}
    inode = ""
    for table in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            lines = pathlib.Path(table).read_text().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            parts = line.split()
            try:
                local = int(parts[1].split(":")[1], 16)
                remote = int(parts[2].split(":")[1], 16)
            except (ValueError, IndexError):
                continue
            if (local, remote) in want:
                inode = parts[9]
                break
        if inode:
            break
    if not inode:
        return 0
    target = f"socket:[{inode}]"
    for proc in pathlib.Path("/proc").iterdir():
        if not proc.name.isdigit():
            continue
        try:
            fds = (proc / "fd").iterdir()
        except OSError:
            continue
        for fd in fds:
            try:
                if pathlib.Path(str(fd)).resolve().as_posix() == target or \
                        str(fd).endswith(target) or \
                        (fd / "").is_symlink() and \
                        pathlib.Path(str(fd)).readlink().as_posix() == target:
                    return int(proc.name)
            except OSError:
                continue
    return 0


def apply_catch_answer(answer, process_path: str, store, host: str = "") -> bool:
    """Review C3: an Always answer on a catch-path card becomes a stored rule
    so the next refresh enforces it in kernel (the "applies onward" promise).
    Once-answers store nothing. Returns whether a rule was written.

    A GHOST (no path) is no longer a dead end (owner 2026-11-13). It used to
    store nothing, which made "Always allow/block" a lie on exactly the cards
    where the program could not be attributed - the owner pressed forever and
    nothing changed, so the queue came back. The destination is known even
    when the program is not, and appfw.rules writes an address rule for it
    (op_kind dst.ip), so a ghost answer is stored against the HOST. The
    program-wide lane still needs a path; the address lane does not.
    """
    if not (answer and len(answer) >= 5 and answer[4] == "always"):
        return False
    action = answer[3]
    if action not in ("allow", "deny"):
        return False
    path = str(process_path or "").strip()
    host = str(host or "").strip()
    if not path and not host:
        return False              # nothing to key a rule on, honestly
    try:
        from appfw.rules import rule_from_decision
        if path:
            rule = rule_from_decision(type("C", (), {"process_path": path})(),
                                      action, "always", host=None)
        else:
            # no path: scope the rule to the one destination we know
            rule = rule_from_decision(type("C", (), {"process_path": ""})(),
                                      action, "always", host=host)
        store.add(rule)
        return True
    except Exception:
        return False


def evaluate_connection(line: str, policy, resolver, ask=None):
    """One kernel GW-DENY line → the chain. None for anything that is
    not ours or not parseable; the chain's own verdict otherwise. The
    chain runs the FULL policy (the kernel already dropped the packet —
    the carried-minor dead `app_rules` param is gone)."""
    if "GW-DENY" not in line:
        return None
    m = _KERNEL_FIELDS.search(line)
    if not m:
        return None
    dst = m.group("dst")
    if m.group("dst6") is not None:
        dst = m.group("dst6")
    try:
        spt, dpt = int(m.group("spt")), int(m.group("dpt"))
    except ValueError:
        return None
    if not 1 <= dpt <= 65535 or not 1 <= spt <= 65535:
        return None
    if m.group("dst6") is None:
        if any(int(octet) > 255 for octet in dst.split(".")):
            return None
    else:
        # v6 shape sanity: colon-compressed hex only, no prefix length
        if ":" not in dst or "/" in dst or "." in dst \
                or not all(c in "0123456789abcdefABCDEF:" for c in dst):
            return None
    proto = (m.group("proto") or "tcp").lower()
    pid = _socket_pid(spt, dpt)
    exe = ""
    if pid:
        try:
            exe = pathlib.Path(f"/proc/{pid}/exe").resolve().as_posix()
        except OSError:
            exe = ""
    conn = Conn(host=dst, dst_ip=dst, dst_port=dpt, proto=proto, pid=pid,
                src_port=spt, path=exe,
                app=pathlib.Path(exe).name if exe else "unknown")
    if resolver is not None:
        try:
            resolver.resolve(conn)            # engine's enrichment
        except Exception:
            pass
    if policy is None:
        return None
    action, duration, _note, _op = __import__("appfw.policy", fromlist=[
        "decide"]).decide(conn, policy, ask=ask)
    # Full chain result so the caller can apply 'always' answers onward
    # (review C3): app, dst, port, action, duration, resolved path.
    return (conn.app_name, dst, dpt, action, duration, exe)
