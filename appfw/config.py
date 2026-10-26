"""appfw.config — the config-first layer (owner order 2026-10-25).

data/appfw/config.json drives the ruleset generator, the worker, and the
UI toggles. Missing file → these defaults (written once, atomically).
ipv6_enabled=false installs NO ip6 rules: IPv6 flows untouched by the
engine (default policy). The kernel exemptions (loopback, port 53) are
ALWAYS present — the two outage lessons, non-negotiable.
"""
from __future__ import annotations

import json
import pathlib
import time

from .atomicio import write_json_atomic

DEFAULTS = {
    "version": 1,
    # IPv6 filtered by default (owner demand 2026-10-25): a fresh install
    # must never ship with half the internet unmonitorable in secret.
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
    """Defaults deep-merged over the file; corrupt → defaults (safe)."""
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
    """The IPv6-aware ruleset generator. ALWAYS: loopback + DNS exemptions
    first (the outage lessons), then the queue with bypass (fail-open)."""
    nfq = int(cfg.get("nfqueue_num", 111))
    # fail_open (the old outage lesson) → "bypass": a dead worker lets
    # traffic OUT rather than trapping the person. fail_open=false → no
    # bypass: a dead worker STALLS outbound TCP (except the DNS/loopback
    # exemptions) instead of leaking it — the knob is real, not
    # decorative (audit 2026-10-25).
    bypass = "bypass" if cfg.get("fail_open", True) else ""
    lines = [
        f"add table inet greywatch_appfw",
        "add chain inet greywatch_appfw out "
        "{ type filter hook output priority 0 ; policy accept ; }",
        # (1) loopback exempt — resolver/UI chatter (incident #1)
        "add rule inet greywatch_appfw out ip daddr 127.0.0.0/8 counter accept",
        "add rule inet greywatch_appfw out ip6 daddr ::1 counter accept",
        # (2) DNS exempt — the resolver lane (incident #1)
        "add rule inet greywatch_appfw out udp dport 53 counter accept",
        "add rule inet greywatch_appfw out tcp dport 53 counter accept",
        # (2b) always-exempt destinations (owner order 2026-10-24: ollama +
        # user network never blockable). Pre-queue ACCEPT — these packets
        # never wait for a verdict at all.
        *[f"add rule inet greywatch_appfw out ip daddr {d} counter accept"
          for d in cfg.get("always_exempt", [])],
        # (3) the queue (ipv4 always, ipv6 only when enabled)
        f"add rule inet greywatch_appfw out ip protocol tcp ct state new "
        f"counter queue num {nfq} {bypass}".rstrip(),
    ]
    if cfg.get("ipv6_enabled"):
        lines.append(
            f"add rule inet greywatch_appfw out ip6 protocol tcp ct state "
            f"new counter queue num {nfq} {bypass}".rstrip())
    return "\n".join(lines) + "\n"