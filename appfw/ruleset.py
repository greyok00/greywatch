"""appfw.ruleset — the greywatch2 nftables table (plan Task 4).

Renders per-app cgroupv2 scope rules + feed IP sets + a trailing catch
deny+LOG. The table is exchanged atomically: `nft -c` (check) validates
the full file first; a failed check or an absent nft leaves the running
ruleset untouched (fail-closed swap). No NFQUEUE in scope mode: the
packet layer answers app questions only.
"""
from __future__ import annotations

import os
import pathlib
import subprocess
import tempfile

from feeds import _valid_ip     # one tokenizer, shared across lanes

TABLE = "greywatch2"


class AppRule:
    __slots__ = ("scope", "basename", "verdict", "note")

    def __init__(self, scope: str, basename: str, verdict: str, note: str = ""):
        self.scope = scope
        self.basename = basename
        self.verdict = verdict          # "allow" | "deny"
        self.note = note

    def as_dict(self) -> dict:
        return {"scope": self.scope, "basename": self.basename,
                "verdict": self.verdict, "note": self.note}


def _nft_quote(token: str) -> str:
    """Quote for an nft double-quoted string: backslash and double-quote
    escapes; control chars are dropped (a scope basename never has them,
    and dropped beats injected)."""
    out = []
    for ch in token:
        if ch in ("\\", '"'):
            out.append("\\" + ch)
        elif ch.isprintable():
            out.append(ch)
        else:
            out.append(" ")
    return "".join(out)


def _set_block(name: str, rows: list[str], comment: str) -> list[str]:
    lines = [f"    set {name} {{", f"        comment \"{_nft_quote(comment)}\""]
    if rows:
        lines.append("        type ipv4_addr; flags interval")
        lines.append("        elements = { " + ", ".join(sorted(rows)) + " }")
    else:
        lines.append("        type ipv4_addr; flags interval")
    lines.append("    }")
    return lines


def _depth_of(path: str) -> int:
    """1-indexed component count from the root (nft's `level N`): a/b/c → 3."""
    parts = [p for p in str(path or "").split("/") if p]
    return len(parts)


def render_ruleset(apps: list[AppRule], feed_sets: dict[str, set[str]],
                   catch: bool = True) -> str:
    """Full ruleset text. Deterministic ordering (sorted scopes, sorted
    set elements) for byte-identical re-renders."""
    lines: list[str] = [f"table inet {TABLE} {{"]

    # -- feed IP sets (validated IPs only; anything else is dropped) ---
    lines.append("    # feed ip sets (deny-or-annotate only, LAW-4)")
    for name in sorted(feed_sets):
        ips = sorted(ip for ip in feed_sets[name] if _valid_ip(ip))
        lines.extend(_set_block(f"gw_{_safe_name(name)}", ips,
                                f"feed {name}"))
    if not feed_sets:
        lines.append("    set gw_empty { type ipv4_addr; flags interval }")

    # -- consumers -----------------------------------------------------
    lines.append("    chain feed-guard {")
    lines.append("        type filter hook output priority -5; policy accept;")
    # RULING (pass-3 M-1, stated where the order is chosen): this chain
    # runs at priority -5, BEFORE the egress chain's per-scope rules —
    # so a feed-set IP is kernel-denied even for a TRUSTED app's traffic
    # (NFQUEUE lane: trust [1] outranks feeds [3]). Deliberate: the
    # kernel lane is deny-biased and feeds are deny-or-annotate only
    # (LAW-4); a wrong allow here is worse than a wrong deny. The
    # exemptions below exist so a hostile feed row can never blackhole
    # the resolver, loopback or LAN.
    lines.append("        ip daddr 127.0.0.0/8 accept comment \"loopback exempt\"")
    lines.append("        ip daddr 192.168.0.0/16 accept comment \"LAN exempt\"")
    lines.append("        ip daddr 10.0.0.0/8 accept comment \"LAN exempt\"")
    lines.append("        ip daddr 172.16.0.0/12 accept comment \"LAN exempt\"")
    lines.append("        ip6 daddr ::1 accept comment \"loopback v6 exempt\"")
    lines.append("        ip6 daddr fc00::/7 accept comment \"LAN v6 exempt\"")
    lines.append("        udp dport 53 accept comment \"dns exempt\"")
    lines.append("        tcp dport 53 accept comment \"dns exempt tcp fallback\"")
    lines.append("        # feeds deny-or-annotate only (LAW-4): named sets drop")
    for name in sorted(feed_sets):
        lines.append(f"        ip daddr @gw_{_safe_name(name)} drop")
    if not feed_sets:
        lines.append("        counter return")
    lines.append("    }")

    # -- per-app rules --------------------------------------------------
    lines.append("    # per-app cgroupv2 scope rules (subject = the PROGRAM)")
    lines.append("    chain egress {")
    lines.append("        type filter hook output priority 0; policy accept;")
    # gate 5's exemptions as kernel facts, BEFORE any scope verdict or
    # the catch rule (review C1: without these the catch rule dropped
    # loopback, LAN and DNS the moment the table swapped in)
    lines.append("        ip daddr 127.0.0.0/8 accept comment \"loopback exempt\"")
    lines.append("        ip daddr 192.168.0.0/16 accept comment \"LAN exempt\"")
    lines.append("        ip daddr 10.0.0.0/8 accept comment \"LAN exempt\"")
    lines.append("        ip daddr 172.16.0.0/12 accept comment \"LAN exempt\"")
    lines.append("        ip6 daddr ::1 accept comment \"loopback v6 exempt\"")
    lines.append("        ip6 daddr fc00::/7 accept comment \"LAN v6 exempt\"")
    lines.append("        udp dport 53 accept comment \"dns exempt\"")
    lines.append("        tcp dport 53 accept comment \"dns exempt tcp fallback\"")
    for rule in sorted(apps, key=lambda r: r.scope):
        quoted = _nft_quote(rule.basename)
        depth = _depth_of(rule.scope)
        if depth < 1:
            continue                  # nothing quotable; catch covers it
        # C1 round 2 (`level N` REQUIRED by grammar, 1-indexed from the
        # root): N derives from the LIVE path so desktop slices at depth
        # 4-5 match; a changed depth mismatches until the next refresh
        # and its traffic cards via catch (deny-biased, never silent).
        level = f"level {depth} "
        if rule.verdict == "allow":
            lines.append(
                '        socket cgroupv2 '
                f"{level}"
                f'"{quoted}"'
                ' counter accept comment "'
                f"{_nft_quote(rule.note or rule.basename)}\"")
        else:
            lines.append(
                '        socket cgroupv2 '
                f"{level}"
                f'"{quoted}"'
                ' counter drop comment "'
                f"{_nft_quote(rule.note or rule.basename)}\"")
    if catch:
        # Re-review 3/C-1: limit FIRST, then log — the token bucket
        # gates the log (bounded journald).
        lines.append('        limit rate 30/minute counter '
                     'log prefix "GW-DENY " '
                     'comment "catch: unscoped or unmatched; the chain '
                     'of scale decides the card"')
        # Re-review 4/P0: the drop must be UNLIMITED and unconditional —
        # a drop riding the limited rule lets overflow fall off the
        # chain into policy accept (deny-then-allow). This rule only
        # ever sees packets the limit already declined.
        lines.append('        counter drop comment "catch overflow: '
                     'unmatched traffic is denied, the card decides the '
                     'appeal"')
    lines.append("    }")
    lines.append("}")
    return "\n".join(lines) + "\n"


def _safe_name(name: str) -> str:
    keep = set("abcdefghijklmnopqrstuvwxyz0123456789-_")
    return "".join(ch if ch in keep else "_" for ch in name.lower())[:47]


def _run(cmd: list[str], timeout: float = 10.0) -> bool:
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return proc.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def swap_ruleset(text: str, nft_bin: str = "nft") -> bool:
    """Two-step atomic exchange: check-validate the full file, then load.
    Any failure leaves the running ruleset untouched (fail-closed)."""
    if not text.strip():
        return False
    # I6: stage PRIVATE — the fixed world-readable /tmp name let a
    # local user pre-plant a symlink for root to follow. The repo
    # standard (status.atomic_replace) is a 0700 staging dir + open-fd
    # write, so reuse it.
    try:
        from status import _stage_for
        stagedir = pathlib.Path(_stage_for(str(pathlib.Path(
            tempfile.gettempdir()) / "greywatch-ruleset.nft")))
        stagedir.mkdir(parents=True, exist_ok=True)
        import os as _os
        _os.chmod(stagedir, 0o700)
        fd, tmpname = tempfile.mkstemp(dir=str(stagedir), prefix=".gw-nft-")
        stage = pathlib.Path(tmpname)
        with _os.fdopen(fd, "w") as fh:
            fh.write(text)
    except (OSError, ImportError):
        return False
    try:
        if not _run([nft_bin, "-c", "-f", str(stage)]):
            return False
        return _run([nft_bin, "-f", str(stage)])
    finally:
        try:
            stage.unlink(missing_ok=True)
        except OSError:
            pass
