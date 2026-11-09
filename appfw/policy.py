from __future__ import annotations

import datetime as _dt
import json
import pathlib
import threading
import time

from . import sites
from .base import is_local_service, is_registry_lookup

MAX_LEDGER_BYTES = 200_000
KEEP_LEDGER_LINES = 1600


class Policy:

    def __init__(self, data_dir, trust_list=None, blocklist=None):
        self.data_dir = pathlib.Path(data_dir)
        self._lock = threading.Lock()
        self._learn_mtime = None
        self._learn_until = 0.0
        self._mode_mtime = None
        self._mode_block = False
        self._verdict_mtime = None
        self._headless_ask = "deny-once"
        self._lb_mtime = None
        self._loopback_ports = frozenset()   # editable in config, see below
        self._blocklist = blocklist
        self._trust = trust_list
        self._recent_learned = {}

    def loopback_ports(self) -> frozenset:
        """The local-service ports, read from config (round-3 audit R6):
        base.LOCAL_SERVICE_PORTS hard-coded {8888, 8899} while the config
        documents loopback_allow as config-editable - two sources that
        silently split the first time one source rewrites the other. The parse
        lives in config.loopback_ports; config's DEFAULTS carry the
        same {8888, 8899}, so every absent/unreadable shape still lands
        on the constants the base module keeps for config-less callers."""
        path = self.data_dir / "config.json"
        from .config import DEFAULTS, loopback_ports as parse_ports
        try:
            mtime = path.stat().st_mtime
        except OSError:
            return parse_ports(DEFAULTS)     # no readable config: defaults
        if mtime != self._lb_mtime or self._loopback_ports is None:
            try:
                cfg = json.loads(path.read_text())
            except (OSError, ValueError, AttributeError, TypeError):
                cfg = {}
            self._loopback_ports = parse_ports(
                cfg if isinstance(cfg, dict) else {})
            self._lb_mtime = mtime
        return self._loopback_ports

    def configured_headless_ask(self) -> str | None:
        """The headless verdict the config actually states, or
        None when no readable config carries it (audit R5 follow-up):
        the deny-once default belongs to the dialog surface (AskGate, a
        dismissed or malformed dialog), while 'no dialog is wired at
        all' keeps the historical fail-open allow - a standalone probe
        with zero configuration must not lock its machine's network."""
        path = self.data_dir / "config.json"
        try:
            value = str(json.loads(path.read_text()).get(
                "headless_ask") or "")
        except (OSError, ValueError, AttributeError, TypeError):
            return None
        return value if value in ("allow-once", "deny-once") else None

    def headless_ask(self) -> str:
        """The configured verdict for an unanswered ask (config's
        ``headless_ask``, deny-once by the  contract). Cached by
        mtime like the other config policy stores: the same value must
        answer a dropped dialog, a missing dialog, and a chain error —
        the documented label is always the verdict actually applied."""
        path = self.data_dir / "config.json"
        try:
            mtime = path.stat().st_mtime
        except OSError:
            mtime = None
        if mtime != self._verdict_mtime:
            try:
                value = str(json.loads(path.read_text()).get(
                    "headless_ask") or "")
            except (OSError, ValueError, AttributeError, TypeError):
                value = ""
            self._headless_ask = ("allow-once" if value == "allow-once"
                                  else "deny-once")
            self._verdict_mtime = mtime
        return self._headless_ask

    def _fallback_answer(self) -> str:
        return "allow" if self.headless_ask() == "allow-once" else "deny"

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
                from status import append_checked
                append_checked(str(path), json.dumps(
                    rec, separators=(",", ":")) + "\n", create_mode=0o600)
            self._trim(path)
        except (OSError, ValueError, TypeError, AttributeError):
            pass

    @staticmethod
    def _trim(path, keep=KEEP_LEDGER_LINES):
        try:
            total = 0
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for _ in fh:
                    total += 1
            if total <= keep:      # line cap first: records, not bytes
                return
            tail = []
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                import collections
                window = collections.deque(maxlen=keep)
                for line in fh:
                    window.append(line.rstrip("\n"))
                tail = list(window)
            from status import atomic_replace
            atomic_replace(str(path), "\n".join(tail) + "\n")
        except OSError:
            pass

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

    def trust_site(self, host: str):
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
            # The entries are names; the packet verdict sees an address.
            # The named entries' resolved addresses ride in the sites
            # cache the engine's slow lane refreshes, so a wizard pick
            # keeps working after the lookup that named it is over.
            v = sites.ip_verdict(self.data_dir, host, tl.allow, tl.block)
            if v:
                return v
            return None
        except Exception:
            return None

    def site_entries(self) -> list[str]:
        """The named entries the sites lane resolves and caches. A trust
        object without the two sets (tests' fakes) counts as none rather
        than raising in a tick."""
        tl = self._trust
        if tl is None:
            return []
        try:
            tl.load()
            return sorted(set(tl.allow) | set(tl.block))
        except Exception:
            return []

    def trust_app(self, path: str, args: list):
        tl = self._trust
        if tl is None:
            return None
        try:
            return tl.decide_app(str(path or ""), list(args or []))
        except Exception:
            return None

    def blocklisted(self, host: str) -> bool:
        bl = self._blocklist
        if bl is None:
            return False
        try:
            return bool(bl.match(str(host or "")))
        except Exception:
            return False


def decide(conn, policy: Policy, store=None, ask=None) -> tuple:
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
        if is_local_service(conn, ports=policy.loopback_ports()):
            return ("allow", "once", "permitted local service", None)
        if is_registry_lookup(conn):
            return ("allow", "once", "permitted registry lookup", None)
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
            opts = [
                {"id": "deny-once", "label": "Block once",
                 "tone": "danger",
                 "helper": "none", "args": ["deny", "once"]},
                {"id": "allow-once", "label": "Allow once",
                 "tone": "primary",
                 "helper": "none", "args": ["allow", "once"]},
            ]
            if conn.process_path:
                # A persistent answer needs a subject that keeps existing.
                # "Always allow" was the only such button, so a program the
                # operator wanted gone asked again and again.
                opts.append({"id": "allow-always",
                             "label": "Always allow this program",
                             "tone": "quiet",
                             "helper": "none", "args": ["allow", "always"]})
                opts.append({"id": "block-always",
                             "label": "Always block this program",
                             "tone": "danger",
                             "helper": "none", "args": ["deny", "always"]})
            opts.append({"id": "trust-site",
                         "label": "Always allow this site",
                         "tone": "quiet",
                         "helper": "none",
                         "args": ["allow", "always", "trust"]})
            opts.append({"id": "block-site",
                         "label": "Always block this site",
                         "tone": "quiet",
                         "helper": "none",
                         "args": ["deny", "always", "trust-block"]})
            spec = {
                "id": (f"appfw:{conn.app_name}:{int(conn.pid or 0)}:"
                       f"{int(conn.src_port or 0)}"),
                "eyebrow": "App firewall",
                "subject": f"{conn.app_name or 'An app'} wants internet "
                           f"access",
                "detail": (f"{conn.process_path or '<unknown path>'}\n"
                           f"→ {host}:{conn.dst_port} ({conn.protocol}) · "
                           f"pid {conn.pid}"),
                "question": "",
                "host": str(host or ""),
                # AskGate's repeat-window dedupe keys on this: without it
                # the anti-bombardment window never engaged, and the same
                # destination re-prompted serially with a full 30 s wait.
                "dst_ip": str(getattr(conn, "dst_ip", "") or ""),
                # Structured facts so the dashboard can draw the identity
                # card without re-parsing the detail line.
                "app_name": str(conn.app_name or ""),
                "path": str(conn.process_path or ""),
                "port": int(conn.dst_port or 0),
                "proto": str(conn.protocol or ""),
                "pid": int(conn.pid or 0),
                "options": opts,
            }
            ans = ask(spec)
            fallback = policy._fallback_answer()
            action = ans[0] if ans and ans[0] in ("allow", "deny") \
                else fallback
            # Not just the falsy answer: a dialog dismissed with a
            # malformed option must not read as "allow" either - that
            # was a hard-coded default deciding for the user (symbolic
            # audit R5), while the config documents deny-once.
            duration = ans[1] if len(ans) > 1 else "once"
            host_op = ans[2] if len(ans) > 2 else None
            # The ask system says who actually decided (/163): a
            # headless timeout or a fast no-dashboard path must not read
            # as "answered: deny" when nobody was watching.
            if len(ans) > 3 and isinstance(ans[3], str) and ans[3]:
                note = ans[3]
            else:
                note = f"answered: {action}"
            return action, duration, note, host_op
        # No dialog is wired at all (standalone probes, tests): the
        # the configured headless verdict answers when config says
        # one, and the historical fail-open allow stands when nothing is
        # configured - a zero-config machine must not lose its network
        # because greywatch runs with no dialog system (audit R5
        # follow-up; the original pins test_fail_open_on_chain_error /
        # test_learning_expires_on_its_own encode that floor).
        configured = policy.configured_headless_ask()
        if configured in ("allow-once", "deny-once"):
            return (configured.replace("-once", ""), "once",
                    f"default {configured} (no dialog wired)", None)
        return ("allow", "once", "default allow-once (no dialog wired)", None)
    except Exception:
        pass
    # The chain dying (a broken policy object, a storage error) is a
    # greywatch fault, not a policy choice: fail open, never a lockout
    # - the machine's network must not depend on our error handling.
    return ("allow", "once", "fail-open (chain error)", None)
