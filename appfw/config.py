from __future__ import annotations

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
    # user approval. Default is deny-once (GW-03): unanswered asks BLOCK
    # rather than silently allow; the cost is possible connectivity loss
    # for programs you never got to approve. Choose "allow-once" only if
    # availability beats enforcement for this machine. The daemon labels
    # whichever choice is live in status.json.
    "headless_ask": "deny-once",
    "pre_seeded_allow": ["brave", "chromium", "python3.13", "node",
                         "ollama", "claude"],
    "loopback_allow": [
        {"port": 8888, "service": "SearXNG"},
        {"port": 8899, "service": "browser control"},
    ],
    "nfqueue_num": 111,
    "nfqueue_copy_range": 256,
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


def build_ruleset(cfg: dict) -> str:
    nfq = int(cfg.get("nfqueue_num", 111))
    # nft grammar: 'queue' takes EITHER a queue number OR flags, never both
    # in one statement without the flags keyword. "queue num 111 bypass" is
    # a SYNTAX ERROR on current libnftnl (verified 2026-10-27: nft rejects
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
          for d in cfg.get("always_exempt", [])],
        f"add rule inet greywatch_appfw out ip protocol tcp ct state new "
        f"counter {queue_stmt}",
    ]
    if cfg.get("ipv6_enabled"):
        # In the inet family a bare "protocol" match needs a family keyword:
        # "ip protocol tcp" is valid, "ip6 protocol tcp" is NOT (ip6 uses
        # nexthdr). "meta nfproto ipv6 protocol tcp" still fails — nfproto
        # selects the family but does not give 'protocol' a family context,
        # and nft rejects it at parse time (owner report 2026-10-27: this
        # one line kept the whole engine from ever arming — the caret in
        # the error sat under this token, column 53, width 8). The portable
        # form is "meta l4proto tcp", which needs no family context.
        lines.append(
            f"add rule inet greywatch_appfw out meta nfproto ipv6 "
            f"meta l4proto tcp ct state new counter {queue_stmt}")
    return "\n".join(lines) + "\n"
