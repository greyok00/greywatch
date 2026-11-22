#!/usr/bin/env python3
"""feeds_lane — oneshot entry for greywatch-feeds.service.

Pulls every feed whose cadence has elapsed (manifest timestamps), keeps
yesterday's set on any failure, applies the web of trust, then:
  - renders the dnsmasq blocklist from the ENFORCED domain rows only,
  - feeds the enforced IP/netblock rows to intelwall (nft gw_intel),
  - writes intel-web.json — the trust report the Network page reads.
A transient per-feed failure keeps yesterday's set, prints to stderr and
still exits 0 (GW-08: a graceful retry must not mark the unit failed);
only an unhandled crash exits nonzero.
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

INTEL_REPORT = "intel-web.json"


def default_data_dir() -> pathlib.Path:
    env = None
    try:
        env = __import__("os").environ.get("GREYWATCH_DATA_DIR")
    except Exception:
        env = None
    return pathlib.Path(env) if env else pathlib.Path("/var/lib/greywatch")


def pull_due(cache: pathlib.Path, now: float) -> list[str]:
    """Pull every feed whose cadence elapsed; returns the failure lines
    (state + reason) for the record. A failed pull keeps yesterday's set
    inside fetch_one; the lane keeps running."""
    manifest = {}
    try:
        manifest = json.loads((cache / "manifest.json").read_text())
    except (OSError, ValueError):
        manifest = {}
    failures = []
    for name, spec in feeds.FEEDS.items():
        pulled_at = float((manifest.get(name) or {}).get("fetched_at") or 0)
        if now - pulled_at < spec.cadence_s and pulled_at > 0:
            continue                      # fresh enough; skip
        result = feeds.fetch_one(spec, now=now, cache_dir=cache)
        if result.state != "ok":
            failures.append(f"{name}: {result.state}"
                            + (f" ({result.reason})" if result.reason else ""))
    return failures


def run_trust_layer(cache: pathlib.Path, data_dir: pathlib.Path,
                    now: float) -> dict:
    """The web-of-trust pass: filtered dnsmasq render, firewall apply,
    and the intel-web.json report for the GUI. Raises nothing that kills
    the lane short of a crash: each step records its own outcome."""
    report: dict = {"generated": now, "sources": {}, "totals": {},
                    "dnsmasq": None, "firewall": None}
    try:
        enforced, trust = feeds.enforced_rows(cache)
        report["sources"] = trust["sources"]
        report["totals"] = trust["totals"]
        # domains only for the resolver; IPs/netblocks ride the firewall
        domain_rows = {name: {row for row in rows
                              if not feeds._valid_ip(row)
                              and "/" not in row}
                       for name, rows in enforced.items()}
        rendered = webguard.render_dnsmasq(
            domain_rows, data_dir / "webguard-blocklist.conf")
        report["dnsmasq"] = {"rendered": rendered}
        if INSTALLED_DNSMASQ_CONF:
            try:
                from status import atomic_replace
                body = (data_dir / "webguard-blocklist.conf").read_text()
                atomic_replace(INSTALLED_DNSMASQ_CONF, body)
            except OSError:
                pass
        reloaded = webguard.reload_dnsmasq()
        report["dnsmasq"]["reload"] = reloaded
        print(f"feeds lane: rendered {rendered} rows, dnsmasq reload: {reloaded}")
        # the IP half: every enforced row that is an address or range
        ip_rows: set[str] = set()
        for rows in enforced.values():
            for row in rows:
                if feeds._valid_ip(row) or "/" in row:
                    ip_rows.add(row)
        try:
            import intelwall
            wall = intelwall.apply(ip_rows, data_dir)
            report["firewall"] = wall
            print(f"feeds lane: intelwall {wall['summary']}"
                  f" (loaded={wall['loaded']})")
        except Exception as exc:            # noqa: BLE001 — never kill the lane
            report["firewall"] = {"error": str(exc)}
            print(f"feeds lane: intelwall unavailable: {exc}", file=sys.stderr)
    except Exception as exc:                # noqa: BLE001
        report["error"] = str(exc)
        print(f"feeds lane: trust layer failed: {exc}", file=sys.stderr)
        raise
    finally:
        try:
            from status import atomic_replace, ui_gid
            atomic_replace(str(data_dir / INTEL_REPORT),
                           json.dumps(report, indent=1, sort_keys=True),
                           gid=ui_gid())
        except OSError as exc:
            print(f"feeds lane: could not write {INTEL_REPORT}: {exc}",
                  file=sys.stderr)
    return report


def main(argv=None) -> int:
    data_dir = default_data_dir()
    cache = data_dir / "feeds"
    failures = pull_due(cache, time.time())
    run_trust_layer(cache, data_dir, time.time())
    if failures:
        for line in failures:
            print(f"feed failure (kept yesterday): {line}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
