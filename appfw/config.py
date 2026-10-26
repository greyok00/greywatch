from __future__ import annotations

import json
import pathlib
import time

from .atomicio import write_json_atomic

DEFAULTS = {
    "version": 1,
    "ipv6_enabled": True,
    "default_policy": "allow-once",
    "learning_mode": True,
    "strict_mode": False,
    "fail_open": True,
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
    bypass = "bypass" if cfg.get("fail_open", True) else ""
    lines = [
        f"add table inet greywatch_appfw",
        "add chain inet greywatch_appfw out "
        "{ type filter hook output priority 0 ; policy accept ; }",
        "add rule inet greywatch_appfw out ip daddr 127.0.0.0/8 counter accept",
        "add rule inet greywatch_appfw out ip6 daddr ::1 counter accept",
        "add rule inet greywatch_appfw out udp dport 53 counter accept",
        "add rule inet greywatch_appfw out tcp dport 53 counter accept",
        *[f"add rule inet greywatch_appfw out ip daddr {d} counter accept"
          for d in cfg.get("always_exempt", [])],
        f"add rule inet greywatch_appfw out ip protocol tcp ct state new "
        f"counter queue num {nfq} {bypass}".rstrip(),
    ]
    if cfg.get("ipv6_enabled"):
        lines.append(
            f"add rule inet greywatch_appfw out ip6 protocol tcp ct state "
            f"new counter queue num {nfq} {bypass}".rstrip())
    return "\n".join(lines) + "\n"
