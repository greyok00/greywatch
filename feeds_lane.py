#!/usr/bin/env python3
"""feeds_lane — oneshot entry for greywatch-feeds.service.

Pulls every feed whose cadence has elapsed (manifest timestamps), keeps
yesterday's set on any failure, re-renders the dnsmasq blocklist and
SIGHUPs the resolver when something changed. Exits 0 on a fully
successful lane; exit 1 lists which feeds failed (the timer keeps the
schedule either way; the manifest is the record).
"""
from __future__ import annotations

import json
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import feeds
import webguard

# Carried minor 6: the conf the resolver ACTUALLY includes (install.sh
# wires dnsmasq.conf → this file). The runtime lane mirrors its rendered
# body here so the resolver always serves the current pull. Overridable
# for tests; empty string disables the mirror (non-root lanes).
INSTALLED_DNSMASQ_CONF = "/etc/dnsmasq.d/greywatch-blocklist.conf"


def default_data_dir() -> pathlib.Path:
    env = None
    try:
        env = __import__("os").environ.get("GREYWATCH_DATA_DIR")
    except Exception:
        env = None
    return pathlib.Path(env) if env else pathlib.Path("/var/lib/greywatch")


def main(argv=None) -> int:
    data_dir = default_data_dir()
    cache = data_dir / "feeds"
    manifest = {}
    try:
        manifest = json.loads((cache / "manifest.json").read_text())
    except (OSError, ValueError):
        manifest = {}
    now = time.time()
    failures = []
    for name, spec in feeds.FEEDS.items():
        pulled_at = float((manifest.get(name) or {}).get("fetched_at") or 0)
        if now - pulled_at < spec.cadence_s and pulled_at > 0:
            continue                      # fresh enough; skip
        result = feeds.fetch_one(spec, now=now, cache_dir=cache)
        if result.state != "ok":
            failures.append(f"{name}: {result.state}"
                            + (f" ({result.reason})" if result.reason else ""))
    rendered = webguard.render_dnsmasq(feeds.cache_set(cache),
                                       data_dir / "webguard-blocklist.conf")
    # Carried minor 6: the runtime refresh must reach the conf the
    # RESOLVER actually includes (the install-day /etc copy would
    # otherwise serve forever until reinstall). Mirror the rendered body
    # into the installed include before the SIGHUP; unwritable is fine
    # (the daemon lane runs as root; test/non-root degrade to no-op).
    if INSTALLED_DNSMASQ_CONF:
        try:
            from status import atomic_replace
            body = (data_dir / "webguard-blocklist.conf").read_text()
            atomic_replace(INSTALLED_DNSMASQ_CONF, body)
        except OSError:
            pass
    reloaded = webguard.reload_dnsmasq()
    print(f"feeds lane: rendered {rendered} rows, dnsmasq reload: {reloaded}")
    if failures:
        for line in failures:
            print(f"feed failure: {line}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
