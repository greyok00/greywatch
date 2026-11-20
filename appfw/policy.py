from __future__ import annotations

import datetime as _dt
import json
import pathlib
import threading
import time

from . import sites
from .base import is_local_service, is_registry_lookup
import threatscale

MAX_LEDGER_BYTES = 200_000
KEEP_LEDGER_LINES = 1600


def _config_file(data_dir) -> pathlib.Path:
    """The one config file for this data dir.

    Owner 2026-11-13: THE bug behind "it is blocking all my hotmail
    connections". The config lives at <data>/appfw/config.json (that is what
    appfw.config.config_path returns, what the wizard writes, and what the
    daemon's _headless_ask reads). This module looked at <data>/config.json
    instead - a file that does not exist on a normal install - so every
    config read here silently fell through to its default. The owner set
    headless_ask=allow-once; the chain read deny-once and refused every
    first contact, mail hosts included, while the UI showed the right
    setting the whole time.

    The legacy <data>/config.json is still honoured when the canonical file
    is absent, so an old install that wrote the flat path does not break.
    """
    canonical = pathlib.Path(data_dir) / "appfw" / "config.json"
    if canonical.exists():
        return canonical
    legacy = pathlib.Path(data_dir) / "config.json"
    if legacy.exists():
        return legacy
    return canonical          # the path we would create/expect


class Policy:

    def __init__(self, data_dir, trust_list=None, blocklist=None,
                 baseline=None, feeds_cache=None):
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
        self._baseline = baseline
        self._feeds_cache = feeds_cache     # path-like; read fresh per verdict
        self._scale = None                  # lazy threatscale.load_scale cache
        self._recent_learned = {}

    def loopback_ports(self) -> frozenset:
        """The local-service ports, read from config (round-3 audit R6):
        base.LOCAL_SERVICE_PORTS hard-coded {8888, 8899} while the config
        documents loopback_allow as config-editable - two sources that
        silently split the first time one source rewrites the other. The parse
        lives in config.loopback_ports; config's DEFAULTS carry the
        same {8888, 8899}, so every absent/unreadable shape still lands
        on the constants the base module keeps for config-less callers."""
        path = _config_file(self.data_dir)
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
        path = _config_file(self.data_dir)
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
        path = _config_file(self.data_dir)
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

    def feed_verdict(self, host: str):
        """(category, feed_name) when the destination is on a pulled
        list; (None, None) otherwise. DENY-or-annotation only by the
        feeds module's construction (LAW-4). The parsed cache is held
        in memory and rebuilt only when the manifest changes (review
        I1: per-connection disk reads blew the worker's 250 ms window).
        On any error the cached copy answers; never the disk hot path."""
        if self._feeds_cache is None:
            return (None, None)
        try:
            manifest = pathlib.Path(self._feeds_cache) / "manifest.json"
            stamp = manifest.stat().st_mtime if manifest.exists() else 0.0
        except OSError:
            stamp = -1.0
        if stamp != getattr(self, "_feeds_stamp", None):
            try:
                import feeds as feeds_mod
                self._feeds_sets = feeds_mod.cache_set(self._feeds_cache)
                self._feeds_stamp = stamp
            except Exception:
                pass                     # keep the previous cached copy
        return self._apply_cached(host)

    def _apply_cached(self, host: str):
        """Lookup against the in-memory sets (never re-parses disk)."""
        sets = getattr(self, "_feeds_sets", None)
        if not sets:
            return (None, None)
        low = (str(host or "").strip().lower().rstrip("."))
        if not low:
            return (None, None)
        parts = low.split(".")
        for cut in range(0, len(parts) - 1):
            candidate = ".".join(parts[cut:])
            for name, rows in sets.items():
                if candidate in rows:
                    try:
                        import feeds as feeds_mod
                        spec = feeds_mod.FEEDS.get(name)
                    except Exception:
                        spec = None
                    return (spec.category if spec else "unknown", name)
            if candidate.replace(".", "").isdigit() and \
                    len(parts) - cut == 4:
                break                    # IPs have no parents
        return (None, None)

    def baseline_verdict(self, app_path: str, host: str, port: int):
        """L1 witness (prior ALLOW for the pair) or None. Reads the
        built Baseline passed in at construction."""
        if self._baseline is None:
            return None
        app = pathlib.Path(app_path or "<unknown>").name
        try:
            import baseline as baseline_mod
            return baseline_mod.profile_verdict(self._baseline, app,
                                                str(host or ""),
                                                int(port or 0))
        except Exception:
            return None

    def anomaly_flags(self, app_path: str, host: str, port: int) -> dict:
        if self._baseline is None:
            return {"first_contact": True, "quiet_app": False,
                    "new_port_class": True}
        app = pathlib.Path(app_path or "<unknown>").name
        try:
            import baseline as baseline_mod
            return baseline_mod.anomaly_inputs(self._baseline, app,
                                               str(host or ""),
                                               int(port or 0))
        except Exception:
            return {"first_contact": True, "quiet_app": False,
                    "new_port_class": True}

    def blocklisted(self, host: str) -> bool:
        bl = self._blocklist
        if bl is None:
            return False
        try:
            return bool(bl.match(str(host or "")))
        except Exception:
            return False

    def site_block_match(self, host: str) -> bool:
        """Review I8 bridge: an operator's site block entry (the
        UI's trust.json auto_block list) keeps a deterministic packet-
        layer effect until the dnsmasq lane is installed. Suffix match
        (subdomains included), same semantics as the downloaded lists.
        Accepts either a raw set of entries or a live TrustList object."""
        blocks = getattr(self, "_site_blocks", None)
        if blocks is None:
            return False
        entries = getattr(blocks, "block", None)
        if entries is None and isinstance(blocks, (set, frozenset, list,
                                                    tuple)):
            entries = blocks
        if not entries:
            return False
        low = str(host or "").strip().lower().rstrip(".")
        if not low:
            return False
        for entry in entries:
            e = str(entry).strip().lower().lstrip("*.")
            if not e:
                continue
            if low == e or low.endswith("." + e):
                return True
        return False


def _risk_score(policy: Policy, conn, anomalies: dict) -> tuple[int, dict[str, bool]]:
    """Deterministic heuristic score (LAW-1: code, not vibes). Components
    and weights are documented in the design; the returned flags ride the
    card so every verdict shows its basis."""
    flags = {
        "first_contact": bool(anomalies.get("first_contact")),
        "quiet_app": bool(anomalies.get("quiet_app")),
        "risky_path": str(getattr(conn, "process_path", "") or "").startswith(
            ("/tmp/", "/var/tmp/", "/run/user/", "/dev/shm/")),
        # Stricter semantics (kept deliberately; ruling wording amended):
        # no attribution OR no pid ⇒ unattributable. A pid-0 conn's path
        # is the resolver's stale-path fallback — identity-DOUBT, and
        # doubtful attribution must never ride the silent lanes (LAW-2:
        # the cost of a wrong silent allow exceeds an extra card).
        "unattributable": ((not str(getattr(conn, "process_path", "") or ""))
                           or (not int(getattr(conn, "pid", 0) or 0))),
    }
    score = 0
    if flags["first_contact"]:
        score += 20
    if flags["quiet_app"]:
        score += 40
    if flags["risky_path"]:
        score += 40
    if flags["unattributable"]:
        # The owner's complaint named exactly this shape: no path, no pid,
        # "unknown app" — an unidentified program never rides L2.
        score += 40
    return score, flags


def _level(policy: Policy, score: int) -> tuple[str, dict]:
    scale, _reason = _load_scale_cached(policy)
    return threatscale.level_for(score, scale), scale


def _load_scale_cached(policy: Policy) -> tuple[dict, str | None]:
    if getattr(policy, "_scale", None) is None:
        policy._scale = threatscale.load_scale(policy.data_dir)
    return policy._scale


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
        # [1] named program trust (legacy lane, unchanged)
        app_verdict = policy.trust_app(conn.process_path, conn.process_args)
        if app_verdict == "allow":
            return ("allow", "always", "auto-allowed (trusted program)", None)
        # [2] local exempt lanes (gate 5, unchanged)
        if is_local_service(conn, ports=policy.loopback_ports()):
            return ("allow", "once", "permitted local service", None)
        if is_registry_lookup(conn):
            return ("allow", "once", "permitted registry lookup", None)
        # [3] feeds: the pulled lists deny or annotate, never allow (LAW-4)
        category, feed_name = policy.feed_verdict(host)
        if category is not None:
            deny_class = category in ("malware", "phishing", "bad-ip")
            anomalies = policy.anomaly_flags(conn.process_path, host,
                                             conn.dst_port)
            _score, flags = _risk_score(policy, conn, anomalies)
            if deny_class and flags["risky_path"]:
                level = "L4"        # evidence + execution risk: a card
                if ask is not None:
                    spec = _card_spec(conn, host, level=level, score=100,
                                      sources={"feed": feed_name,
                                               "category": category},
                                      flags=flags, policy=policy)
                    ans = ask(spec)
                    return _answered(policy, ans)
            # tracker/ads rows and calm deny-class rows: silent deny,
            # grouped row (gate 3: sites never interrogate)
            return ("deny", "once",
                    f"blocked by {feed_name} ({category} feed): {host}",
                    None)
        # legacy blocklist lane (unchanged wording, same silent shape)
        if policy.blocklisted(host):
            return ("deny", "once",
                    f"blocked by the downloaded list: {host}", None)
        # Review I8 bridge: the operator's site-block entries deny
        # silently at the packet layer (gate 3: sites never ask; the
        # dnsmasq lane supersedes this in a later phase).
        try:
            if policy.site_block_match(host):
                return ("deny", "once",
                        f"blocked by the operator's site block list: "
                        f"{host}", None)
        except Exception:
            pass
        # [4] baseline witness: the pair was ALLOWED before → L1 silent
        witness = policy.baseline_verdict(conn.process_path, host,
                                          conn.dst_port)
        if witness is not None:
            return ("allow", "once",
                    f"baseline: {witness['allows']} prior allows, "
                    f"{witness['count']} contacts", None)
        try:
            if policy.learning_active():
                policy.record_learned(conn)
                return ("allow", "once",
                        f"learning: {conn.app_name} → {host} allowed once "
                        "(recorded)", None)
        except Exception:
            pass
        try:
            # The operator's standing directive (whitelist mode) outranks
            # everything heuristic below: unknown programs are denied
            # regardless of score. Established pairs and local exemptions
            # above are NOT unknown; scoring only decides card-vs-silent
            # for what remains.
            if policy.block_unknown():
                policy.record_learned(conn)
                return ("deny", "once",
                        f"blocked (not trusted): {conn.app_name} → {host}",
                        None)
        except Exception:
            pass
        # [5] heuristic score → level (design §6.1 [5])
        anomalies = policy.anomaly_flags(conn.process_path, host,
                                         conn.dst_port)
        score, flags = _risk_score(policy, conn, anomalies)
        level, _scale = _level(policy, score)
        if level in ("L1", "L2"):
            # silent allow with a recorded note (first contact surfaces
            # as a grouped row, never a popup — gate 3)
            note = (f"first contact, feeds clean (score {score})"
                    if flags["first_contact"]
                    else f"feeds clean, no anomalies (score {score})")
            return ("allow", "once", note, None)
        # [6] L3/L4: DENIED at the gate; ONE card; the card never expires.
        # Flood guard (owner 2026-11-10 no-flood law, reinforced 2026-11-12
        # after 1,005 "<unknown> wants internet access" cards): an
        # UNATTRIBUTABLE flow (no path, no pid) can never be answered by a
        # human — the card carries no fact the owner could use. Only the
        # MEDIUM changes: silent, one event line, never a card.
        #
        # The guard changes the MEDIUM, never a stated choice: whatever
        # the owner configured is still the verdict. When NO config is
        # readable it fails OPEN, because an unattributable flow cannot be
        # answered by anyone - it carries no fact a human could act on - so
        # denying it is a permanent lockout of whatever the owner runs.
        # The owner hit exactly that (2026-11-13, "I NEVER blocked
        # hotmail"): mail hosts failed attribution, attributed traffic
        # sailed through, and there was no card to answer. The guard exists
        # to keep the CARD out of the owner's face, not to hold the network
        # hostage.
        if flags["unattributable"]:
            configured = policy.configured_headless_ask()
            if configured in ("allow-once", "deny-once"):
                verdict = configured.replace("-once", "")
                why = f"default {configured}"
            else:
                verdict = "allow"
                why = "no config read; fail open"
            return (verdict, "once",
                    f"unattributable → {host} {verdict} without asking "
                    f"({why}; {level}, score {score}; flood guard)",
                    None)
        if ask is not None:
            sources = {}
            if feed_name:
                sources["feed"] = feed_name
                sources["category"] = category
            spec = _card_spec(conn, host, level=level, score=score,
                              sources=sources, flags=flags, policy=policy)
            ans = ask(spec)
            return _answered(policy, ans)
        configured = policy.configured_headless_ask()
        if configured in ("allow-once", "deny-once"):
            return (configured.replace("-once", ""), "once",
                    f"default {configured} (no dialog wired; {level}, "
                    f"score {score})", None)
        return ("allow", "once", "default allow-once (no dialog wired)", None)
    except Exception:
        pass
    # The chain dying (a broken policy object, a storage error) is a
    # greywatch fault, not a policy choice: fail open, never a lockout
    # - the machine's network must not depend on our error handling.
    return ("allow", "once", "fail-open (chain error)", None)


def _answered(policy: Policy, ans) -> tuple:
    """Answer handling (unchanged semantics): the verdict comes from a
    verified answer, the fallback otherwise; who decided always says so."""
    fallback = policy._fallback_answer()
    action = ans[0] if ans and ans[0] in ("allow", "deny") else fallback
    duration = ans[1] if len(ans) > 1 else "once"
    host_op = ans[2] if len(ans) > 2 else None
    if len(ans) > 3 and isinstance(ans[3], str) and ans[3]:
        note = ans[3]
    else:
        note = f"answered: {action}"
    return action, duration, note, host_op


def _card_key(conn, host: str) -> str:
    """The stable part of a card id: app + destination (not the port,
    not the pid, not the ephemeral source port). Retries collapse into
    one pending card (carried minor 1)."""
    app = str(getattr(conn, "app_name", "") or "unknown")
    dst = str(host or getattr(conn, "dst_ip", "") or "")
    return f"{app}:{dst}"[:200]


def _card_spec(conn, host: str, level: str, score: int, sources: dict,
               flags: dict, policy: Policy) -> dict:
    """The full-analysis card: every fact the chain has, named. Levels
    ride the spec so the dashboard, CLI and sweep all see the same truth
    (design §6.1 [card], §8 gate 1)."""
    opts = [
        {"id": "deny-once", "label": "Block once", "tone": "danger",
         "helper": "none", "args": ["deny", "once"]},
        {"id": "allow-once", "label": "Allow once", "tone": "primary",
         "helper": "none", "args": ["allow", "once"]},
    ]
    # The "always" half must exist even when the PROGRAM is unknown.
    #
    # Owner 2026-11-13, with the dialog on screen: "<unknown> wants internet
    # access" offered only Block once / Allow once - no forever answer - so
    # a program that could not be attributed could only ever be blocked one
    # address at a time and the queue could never be ended. The bug was that
    # the always-options were gated on conn.process_path, and an
    # UNATTRIBUTABLE flow (pid 0, no path) is exactly the case that never
    # has one - the two facts are anti-correlated, so the answer the owner
    # needs most was offered least.
    #
    # The HOST is known in every one of these cards, and appfw.rules already
    # writes an address rule for it (validate() with op_kind dst.ip), so the
    # host lane is available regardless of attribution. Program-wide rules
    # stay gated: there is no path to key them on, and a phantom catch-all
    # rule is refused by the rule store on purpose.
    if conn.process_path:
        opts.append({"id": "allow-always",
                     "label": "Always allow this program", "tone": "quiet",
                     "helper": "none", "args": ["allow", "always"]})
        opts.append({"id": "block-always",
                     "label": "Always block this program", "tone": "danger",
                     "helper": "none", "args": ["deny", "always"]})
    else:
        # Address-scoped forever answers: always available, because the
        # destination is the one fact an unattributable flow does have.
        opts.append({"id": "allow-site",
                     "label": "Always allow this address", "tone": "quiet",
                     "helper": "none", "args": ["allow", "always"]})
        opts.append({"id": "block-site",
                     "label": "Always block this address", "tone": "danger",
                     "helper": "none", "args": ["deny", "always"]})
    return {
        # Key-stable card id (carried minor 1): keyed on the PROGRAM +
        # DESTINATION, not the ephemeral pid/src_port — a retried or
        # multi-port connection re-opens the SAME pending ask instead of
        # minting a new asks/<hash>.json every window edge (the pending
        # queue can only shrink — pass-3 finding). The pid stays in the
        # detail line for humans; the id is the stable key.
        "id": f"appfw:{conn.app_name}:{_card_key(conn, host)}",
        "eyebrow": f"App firewall — {level} (score {score})",
        "subject": f"{conn.app_name or 'An app'} wants internet access",
        "detail": (f"{conn.process_path or '<unknown path>'}\n"
                   f"→ {host}:{conn.dst_port} ({conn.protocol}) · "
                   f"pid {conn.pid}"),
        "question": "",
        "host": str(host or ""),
        "dst_ip": str(getattr(conn, "dst_ip", "") or ""),
        "app_name": str(conn.app_name or ""),
        "path": str(conn.process_path or ""),
        "port": int(conn.dst_port or 0),
        "proto": str(conn.protocol or ""),
        "pid": int(conn.pid or 0),
        "level": level,
        "score": int(score),
        "sources": sources,
        "flags": flags,
        "options": opts,
    }
