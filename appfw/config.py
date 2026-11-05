from __future__ import annotations

import ipaddress
import json
import pathlib

from .atomicio import write_json_atomic

DEFAULTS = {
    "version": 1,
    "ipv6_enabled": True,
    "default_policy": "allow-once",
    "learning_mode": True,
    "strict_mode": False,
    "fail_open": True,
    # No approval dialog exists in headless/root operation. When the rule
    # engine reaches the "ask" step (unknown program, unknown host), this
    # is what is answered INSTEAD of user approval — so it does NOT mean
    # user approval. Default is deny-once: unanswered asks BLOCK
    # rather than silently allow; the cost is possible connectivity loss
    # for programs you never got to approve. Choose "allow-once" only if
    # availability beats enforcement for this machine. The daemon labels
    # whichever choice is live in status.json.
    "headless_ask": "deny-once",
    "loopback_allow": [
        {"port": 8888, "service": "SearXNG"},
        {"port": 8899, "service": "browser control"},
    ],
    "nfqueue_num": 111,
    "nfqueue_copy_range": 256,
    # How long a prompt may sit unanswered before the engine takes the
    # configured headless verdict, and how long one destination's answer
    # suppresses further prompts (ports change per connection; a random
    # address must not be able to bombard the desktop user).
    "ask_timeout_sec": 30,
    "ask_repeat_window_sec": 300,
    "reconcile_interval_sec": 2,
    "heartbeat_interval_sec": 5,
}

CONFIG_NAME = "config.json"


def config_path(data_dir) -> pathlib.Path:
    return pathlib.Path(data_dir) / "appfw" / CONFIG_NAME


def load(data_dir) -> dict:
    cfg = dict(DEFAULTS)
    try:
        doc = json.loads(config_path(data_dir).read_text())
        if isinstance(doc, dict):
            cfg.update(doc)                  # top-level merge; lists replace
    except (OSError, ValueError):
        pass
    return cfg


def save(data_dir, cfg: dict) -> None:
    p = config_path(data_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    write_json_atomic(p, cfg)


def mtime(data_dir) -> float:
    try:
        return config_path(data_dir).stat().st_mtime
    except OSError:
        return 0.0


def mode_of(cfg: dict) -> str:
    """The one name the UI, the daemon and the engine all use.

    learning  — everything is decided and logged, nothing is enforced.
    standard  — rules are enforced, unanswered prompts fail open.
    whitelist — only explicitly approved traffic; unanswered prompts fail
                closed, with the engine's safety valve as the way back.
    """
    if cfg.get("learning_mode"):
        return "learning"
    if cfg.get("strict_mode") and not cfg.get("fail_open", True):
        return "whitelist"
    return "standard"


def loopback_ports(cfg: dict) -> frozenset:
    """The local-service ports the engine auto-allows, in one parse
    (round-3 audit R6 - the single source). An emptiable list means "no automatic loopback
    permits". A mangled or absent list falls back to the defaults, so
    a hand-edit can only DENY services, not silently re-permit them.
    (base.LOCAL_SERVICE_PORTS stays as the default set for callers
    that have no config in hand - the tests, chiefly.)"""
    rows = cfg.get("loopback_allow")
    if not isinstance(rows, list):
        rows = DEFAULTS["loopback_allow"]
    ports = set()
    for row in rows:
        if isinstance(row, dict):
            try:
                p = int(row.get("port", 0))
            except (TypeError, ValueError, AttributeError):
                continue
            if 1 <= p <= 65535:
                ports.add(p)
    return frozenset(ports)


def queue_num(cfg: dict) -> int:
    """The one queue number the worker binds, the ruleset sends to, and
    the UI shows: derived in one place so a hand-edited config cannot
    leave the ruleset and the worker pulling different queues."""
    nfq = cfg.get("nfqueue_num", 111)
    try:
        nfq = int(nfq)
    except (TypeError, ValueError):
        nfq = 111
    return nfq if 0 <= nfq <= 65535 else 111


def _sanitize(cfg: dict) -> dict:
    """Owner- or tool-edited values must not take the nft ruleset (and
    with it the engine arm) down with a trace-back: a bad queue number
    falls back to the default and an exempt list that survived a JSON
    round-trip as a bare string still becomes one valid rule."""
    cfg["nfqueue_num"] = queue_num(cfg)
    exempt = cfg.get("always_exempt", [])
    if isinstance(exempt, str):
        exempt = [exempt] if exempt.strip() else []
    elif not isinstance(exempt, list):
        exempt = []
    else:
        exempt = [str(item).strip() for item in exempt]
    # The ruleset emits "ip daddr <d>" - an IPv6 or name entry there is
    # an nft parse error that took the whole arm down (audit,
    # so anything that is not a valid IPv4 host or network is dropped.
    clean = []
    for d in exempt:
        try:
            ipaddress.ip_network(d, strict=False)
        except ValueError:
            continue
        # A bare "0.0.0.0" is the same /32 drop-everything as "0.0.0.0/0"
        # once ip_network normalizes it - exempting it exempts the
        # whole internet (round-3 audit R3-F9).
        if d in ("0.0.0.0", "0.0.0.0/0", "::/0", "::") or ":" in d:
            continue
        if d not in clean:
            clean.append(d)
    cfg["always_exempt"] = clean
    return cfg


def build_ruleset(cfg: dict) -> str:
    cfg = _sanitize(cfg)
    nfq = cfg["nfqueue_num"]
    # nft grammar: 'queue' takes EITHER a queue number OR flags, never both
    # in one statement without the flags keyword. "queue num 111 bypass" is
    # a SYNTAX ERROR on current libnftnl (verified: nft rejects
    # it with "syntax error, unexpected string" at exactly that token).
    # Correct form: "queue flags bypass num 111" (fail-open) or
    # "queue num 111" (fail-closed).
    queue_stmt = (f"queue flags bypass num {nfq}" if cfg.get("fail_open", True)
                  else f"queue num {nfq}")
    lines = [
        "add table inet greywatch_appfw",
        "add chain inet greywatch_appfw out "
        "{ type filter hook output priority 0 ; policy accept ; }",
        "add rule inet greywatch_appfw out ip daddr 127.0.0.0/8 counter accept",
        "add rule inet greywatch_appfw out ip6 daddr ::1 counter accept",
        "add rule inet greywatch_appfw out udp dport 53 counter accept",
        "add rule inet greywatch_appfw out tcp dport 53 counter accept",
        *[f"add rule inet greywatch_appfw out ip daddr {d} counter accept"
          for d in cfg["always_exempt"]],
        f"add rule inet greywatch_appfw out ip protocol tcp ct state new "
        f"counter {queue_stmt}",
    ]
    if cfg.get("ipv6_enabled"):
        # In the inet family a bare "protocol" match needs a family keyword:
        # "ip protocol tcp" is valid, "ip6 protocol tcp" is NOT (ip6 uses
        # nexthdr). "meta nfproto ipv6 protocol tcp" still fails — nfproto
        # selects the family but does not give 'protocol' a family context,
        # and nft rejects it at parse time: this
        # one line kept the whole engine from ever arming — the caret in
        # the error sat under this token, column 53, width 8). The portable
        # form is "meta l4proto tcp", which needs no family context.
        lines.append(
            f"add rule inet greywatch_appfw out meta nfproto ipv6 "
            f"meta l4proto tcp ct state new counter {queue_stmt}")
    return "\n".join(lines) + "\n"
