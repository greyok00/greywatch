"""appfw.policy — one decision chain for the whole suite.

Order (same semantics as the chain that came before):
trust site → trusted program → permitted local services → downloaded block
list → learning mode (allow once + record) → block-unknown (deny once +
record) → explicit ask (blocking, only when the dialog is wired) → default
allow once. Lists the person edits in the GUI take effect on the NEXT
decision because the backing files are re-read on mtime change.

decide() returns a 4-tuple `(action, duration, note, host_op)` — host_op
is the site to key a saved rule on when the answer is trust-based.
Fail-open: any unexpected error answers allow-once, never a lockout.
"""
from __future__ import annotations

import datetime as _dt
import json
import pathlib
import threading
import time

from .base import is_local_service

MAX_LEDGER_BYTES = 200_000
KEEP_LEDGER_LINES = 1200


class Policy:
    """Learning / block-unknown / trust / blocklist inputs, re-read on mtime."""

    def __init__(self, data_dir, trust_list=None, blocklist=None):
        self.data_dir = pathlib.Path(data_dir)
        self._lock = threading.Lock()
        self._learn_mtime = None
        self._learn_until = 0.0
        self._mode_mtime = None
        self._mode_block = False
        self._blocklist = blocklist
        self._trust = trust_list
        # Per-pair dedupe: a retry storm must not write one ledger line per
        # SYN (2026-10-25 outage filled the daemon's memory/CPU budget).
        self._recent_learned = {}

    # ── learning mode: allow once, record the pair, grant nothing ──────
    def learning_active(self) -> bool:
        path = self.data_dir / "learning.json"
        try:
            mtime = path.stat().st_mtime
        except OSError:
            self._learn_mtime, self._learn_until = None, 0.0
            return False
        if mtime != self._learn_mtime:
            try:
                self._learn_until = float(
                    json.loads(path.read_text()).get("until") or 0)
            except (OSError, ValueError, TypeError, AttributeError):
                self._learn_until = 0.0
            self._learn_mtime = mtime
        return self._learn_until > time.time()

    def record_learned(self, conn) -> None:
        """Append one seen program/site pair for the person to approve.
        Bounded, best-effort: never blocks or breaks a connection."""
        try:
            key = (str(conn.process_path or ""), str(conn.host or ""),
                   int(conn.dst_port or 0), str(conn.protocol or ""))
            now = time.time()
            if now - self._recent_learned.get(key, 0.0) < 60.0:
                return
            if len(self._recent_learned) > 4096:
                self._recent_learned.clear()
            self._recent_learned[key] = now
            rec = {"ts": _dt.datetime.now(_dt.timezone.utc).isoformat(
                       timespec="seconds"),
                   "app": str(conn.process_path or ""),
                   "host": str(conn.host or ""),
                   "port": int(conn.dst_port or 0),
                   "proto": str(conn.protocol or "")}
            path = self.data_dir / "learning-seen.jsonl"
            with self._lock:
                with path.open("a") as f:
                    f.write(json.dumps(rec, separators=(",", ":")) + "\n")
            self._trim(path)
        except (OSError, ValueError, TypeError, AttributeError):
            pass

    @staticmethod
    def _trim(path, keep=KEEP_LEDGER_LINES):
        """Keep the review list bounded (it is a list, not a log)."""
        try:
            if path.stat().st_size < MAX_LEDGER_BYTES:
                return
            lines = path.read_text(errors="replace").splitlines()[-keep:]
            path.write_text("\n".join(lines) + "\n")
        except OSError:
            pass

    # ── block-unknown: the person's strict mode ─────────────────────────
    def block_unknown(self) -> bool:
        path = self.data_dir / "firewall-mode.json"
        try:
            mtime = path.stat().st_mtime
        except OSError:
            self._mode_mtime, self._mode_block = None, False
            return False
        if mtime != self._mode_mtime:
            try:
                self._mode_block = bool(
                    json.loads(path.read_text()).get("block_unknown"))
            except (OSError, ValueError, TypeError, AttributeError):
                self._mode_block = False
            self._mode_mtime = mtime
        return self._mode_block

    # ── trust list + block list: re-loaded per decision ─────────────────
    def trust_site(self, host: str):
        """None = no verdict; otherwise 'allow'/'deny' (list re-read first).
        An explicit TRUST entry always wins over everything below. The
        list's raw verdict is 'block' — mapped to the action word here."""
        tl = self._trust
        if tl is None:
            return None
        try:
            tl.load()
            v = tl.decide(str(host or ""))
            if v == "allow":
                return "allow"
            if v in ("block", "deny"):
                return "deny"
            return None
        except Exception:
            return None

    def trust_app(self, path: str, args: list):
        """Verdict for a trusted PROGRAM: a named program never asks."""
        tl = self._trust
        if tl is None:
            return None
        try:
            return tl.decide_app(str(path or ""), list(args or []))
        except Exception:
            return None

    def blocklisted(self, host: str) -> bool:
        """Downloaded tracker/malware list; an explicit TRUST still wins."""
        bl = self._blocklist
        if bl is None:
            return False
        try:
            return bool(bl.match(str(host or "")))
        except Exception:
            return False


def decide(conn, policy: Policy, store=None, ask=None) -> tuple:
    """Run the chain for one connection → (action, duration, note, host_op).

    store is consulted first (saved rules outrank the mode switches);
    ask, when given, is called with a spec dict and may block — it is
    only wired when the dialog bridge is switched on.
    """
    try:
        if store is not None:
            try:
                rule = store.decide(conn)
            except Exception:
                rule = None
            if rule is not None:
                return rule.action, "once", f"rule {rule.name}", None
        host = conn.host
        verdict = policy.trust_site(host)
        if verdict:
            return verdict, "always", f"auto-{verdict} (trust list): {host}", host
        app_verdict = policy.trust_app(conn.process_path, conn.process_args)
        if app_verdict == "allow":
            return ("allow", "always", "auto-allowed (trusted program)", None)
        if is_local_service(conn):
            return ("allow", "once", "permitted local service", None)
        if policy.blocklisted(host):
            return ("deny", "once",
                    f"blocked by the downloaded list: {host}", None)
        try:
            if policy.learning_active():
                policy.record_learned(conn)
                return ("allow", "once",
                        f"learning: {conn.app_name} → {host} allowed once "
                        "(recorded)", None)
        except Exception:
            pass
        try:
            if policy.block_unknown():
                policy.record_learned(conn)
                return ("deny", "once",
                        f"blocked (not trusted): {conn.app_name} → {host}",
                        None)
        except Exception:
            pass
        if ask is not None:
            spec = {
                "id": (f"appfw:{conn.app_name}:{int(conn.pid or 0)}:"
                       f"{int(conn.src_port or 0)}"),
                "question": (f"App firewall: {conn.process_path or '<unknown>'}"
                             f"\ndst {host}:{conn.dst_port}"
                             f" ({conn.protocol}) by {conn.pid}"),
                "host": str(host or ""),
                "options": [
                    {"id": "allow-once", "label": "Allow once",
                     "helper": "none", "args": ["allow", "once"]},
                    {"id": "deny-once", "label": "Deny once",
                     "helper": "none", "args": ["deny", "once"]},
                    {"id": "allow-always", "label": "Allow forever",
                     "helper": "none", "args": ["allow", "always"]},
                    {"id": "trust-site",
                     "label": "TRUST this site always (auto-allow)",
                     "helper": "none",
                     "args": ["allow", "always", "trust"]},
                    {"id": "block-site",
                     "label": "BLOCK this site always (auto-deny)",
                     "helper": "none",
                     "args": ["deny", "always", "trust-block"]},
                ],
            }
            ans = ask(spec)
            action = ans[0] if ans else "allow"
            duration = ans[1] if len(ans) > 1 else "once"
            host_op = ans[2] if len(ans) > 2 else None
            return action, duration, f"answered: {action}", host_op
        return ("allow", "once", "default allow-once (no dialog wired)", None)
    except Exception:
        pass
    return ("allow", "once", "fail-open (chain error)", None)