"""webguard — DNS-layer blocklist enforcement (plan Task 3).

The resolver answers the website questions the packet layer used to
ask: ads, trackers, malware and phishing domains go to NXDOMAIN via
dnsmasq conf-file blocks rendered from the feed cache. Every browser
inherits the same lists. IP rows are NOT rendered here — they are the
nftables lane (plan Task 4).
"""
from __future__ import annotations

import os
import pathlib
import signal

from feeds import _valid_host     # one token validator, two consumers

HEADER = "# greywatch webguard (rendered from feeds; do not edit)\n"
DNsmasq_pidfiles = ("/run/dnsmasq/dnsmasq.pid", "/run/dnsmasq.pid")


def render_dnsmasq(cache: dict[str, set[str]], out_path) -> int:
    """Atomic render of `address=/domain/` rows, deduped across feeds,
    domains only. Returns the row count. tmp+rename leaves no debris."""
    merged: set[str] = set()
    for rows in (cache or {}).values():
        merged.update(rows)
    lines = ["# greywatch webguard (rendered from feeds; do not edit)\n"]
    from feeds import _valid_ip
    for raw in sorted(merged):
        d = raw.rstrip(".")
        if _valid_ip(d):
            continue                  # IP rows are the nft lane, not DNS
        if _valid_host(d) and len(d) <= 253:
            lines.append(f"address=/{d}/\n")
    from status import atomic_replace
    atomic_replace(str(out_path), "".join(lines))
    return len(lines) - 1


def reload_dnsmasq(pidfile=None) -> bool:
    """SIGHUP the running dnsmasq; False (never a crash) when the pid
    file is absent or unreadable — the service records the state, and
    the next successful render + reload retries."""
    if pidfile is None:
        for candidate in DNsmasq_pidfiles:
            if pathlib.Path(candidate).exists():
                pidfile = candidate
                break
    if pidfile is None:
        return False
    try:
        pid = int(pathlib.Path(pidfile).read_text().strip())
    except (OSError, ValueError):
        return False
    if pid <= 0:
        return False
    try:
        os.kill(pid, signal.SIGHUP)
    except (OSError, ProcessLookupError):
        return False
    return True


def blocked_by_guard(host: str, conf_path) -> bool:
    """Self-check: is this host in the rendered block file? (Parent-domain
    semantics match dnsmasq: address=/parent/ covers subdomains.)"""
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return False
    try:
        for line in pathlib.Path(conf_path).read_text().splitlines():
            if not line.startswith("address=/"):
                continue
            parent = line[len("address=/"):].rstrip("/").strip()
            if host == parent or host.endswith("." + parent):
                return True
    except OSError:
        return False
    return False


if __name__ == "__main__":                        # feeds_lane/install CLI
    import sys
    env = os.environ.get("GREYWATCH_DATA_DIR")
    if not env or not sys.argv[1:] or sys.argv[1] != "--render":
        print("usage: GREYWATCH_DATA_DIR=<dir> webguard.py --render",
              file=sys.stderr)
        raise SystemExit(2)
    data = pathlib.Path(env)
    cache = data / "feeds"
    merged: dict[str, set[str]] = {}
    if cache.is_dir():
        for f in sorted(cache.glob("*.txt")):
            try:
                rows = {ln.strip() for ln in f.read_text(
                    errors="replace").splitlines() if ln.strip()}
            except OSError:
                continue
            name = f.stem
            valid = [r for r in rows if _valid_host(r)]
            merged[name] = set(valid)
    n = render_dnsmasq(merged, data / "webguard-blocklist.conf")
    print(f"webguard: rendered {n} rows")
    raise SystemExit(0)
