"""intelwall — the auto-enforced firewall layer for web-of-trust IP intel.

The tier-1/tier-2 enforced IP set from feeds.enforced_rows() lands here:
a dedicated nftables table (inet gw_intel) drops inbound, outbound and
forwarded traffic to/from the listed hosts and netblocks. The table is
ours alone — applying it never flushes or touches any other nftables
state, and the elements file is regenerated wholesale from the enforced
set, so an apply is always idempotent. Rendering collapses overlapping
or adjacent ranges first: nftables refuses to load an interval set
whose elements overlap.
"""
from __future__ import annotations

import ipaddress
import os
import pathlib
import shutil
import subprocess
import sys

NFT_FILE = "gw-intel.nft"
TABLE = "gw_intel"


def render_elements(ips) -> tuple[str, str, int]:
    """(nft file body, summary, count). Pure. ips is an iterable of bare
    addresses and CIDR strings; anything unparsable is dropped. Returns
    the full `nft -f` body for the gw_intel table, a one-line summary,
    and the number of enforced elements."""
    nets: list = []
    bad = 0
    for token in ips:
        try:
            nets.append(ipaddress.ip_network(str(token), strict=False))
        except ValueError:
            bad += 1
    v4 = ipaddress.collapse_addresses([n for n in nets if n.version == 4])
    v6 = ipaddress.collapse_addresses([n for n in nets if n.version == 6])
    v4 = sorted(v4)
    v6 = sorted(v6)
    def _set(name: str, kind: str, nets_list) -> list[str]:
        body = [f'    set {name} {{', f'        type {kind}',
                '        flags interval']
        if nets_list:
            body.append(f'        elements = {{ '
                        f'{", ".join(str(n) for n in nets_list)} }}')
        body.append('    }')
        return body

    lines = ['#!/usr/sbin/nft -f',
             '# Managed by greywatch feeds_lane — regenerated wholesale.',
             f'table inet {TABLE} {{']
    lines += _set("intel4", "ipv4_addr", v4)
    lines += _set("intel6", "ipv6_addr", v6)
    lines += [
             '    chain input {',
             '        type filter hook input priority -10; policy accept;',
             '        ip saddr @intel4 drop',
             '        ip6 saddr @intel6 drop',
             '    }',
             '    chain output {',
             '        type filter hook output priority -10; policy accept;',
             '        ip daddr @intel4 drop',
             '        ip6 daddr @intel6 drop',
             '    }',
             '    chain forward {',
             '        type filter hook forward priority -10; policy accept;',
             '        ip saddr @intel4 drop',
             '        ip daddr @intel4 drop',
             '        ip6 saddr @intel6 drop',
             '        ip6 daddr @intel6 drop',
             '    }',
             '}']
    count = len(v4) + len(v6)
    summary = (f"{len(v4)} ipv4 + {len(v6)} ipv6 ranges"
               + (f" ({bad} unparsable dropped)" if bad else ""))
    return "\n".join(lines) + "\n", summary, count


def _euid() -> int:
    return os.geteuid()


def _nft_path() -> str | None:
    return shutil.which("nft")


def _write_file(body: str, data_dir: pathlib.Path) -> pathlib.Path:
    from status import atomic_replace, ui_gid
    out = pathlib.Path(data_dir) / NFT_FILE
    atomic_replace(str(out), body, gid=ui_gid())
    return out


def apply(ips, data_dir, run=None) -> dict:
    """Render the enforced set, store the nft file, and (root + nft
    present) load it. Non-root or nft-less environments store the file
    and apply nothing — apply_stored() re-runs it on the daemon's boot
    pass. `run` stands in for subprocess.run in tests."""
    data_dir = pathlib.Path(data_dir)
    body, summary, count = render_elements(ips)
    path = _write_file(body, data_dir)
    result = {"stored": str(path), "count": count, "summary": summary,
              "loaded": False}
    runner = run or subprocess.run
    nft = _nft_path()
    if nft is None:
        return result

    if _euid() != 0:
        return result
    try:
        done = runner([nft, "-f", str(path)], capture_output=True, timeout=30)
        result["loaded"] = done.returncode == 0
        if done.returncode != 0 and getattr(done, "stderr", None):
            result["error"] = done.stderr.decode(errors="replace")[:500]
    except (OSError, subprocess.SubprocessError) as exc:
        result["error"] = str(exc)
    return result


def apply_stored(data_dir, run=None) -> dict:
    """Boot pass: reload the last stored elements file, if any."""
    data_dir = pathlib.Path(data_dir)
    path = data_dir / NFT_FILE
    try:
        path.read_text()
    except OSError:
        return {"stored": None, "loaded": False}
    nft = _nft_path()
    result = {"stored": str(path), "loaded": False}
    if nft is None:
        return result

    if _euid() != 0:
        return result
    runner = run or subprocess.run
    try:
        # render through the file we stored: nft loads it as-is
        done = runner([nft, "-f", str(path)], capture_output=True, timeout=30)
        result["loaded"] = done.returncode == 0
        if done.returncode != 0 and getattr(done, "stderr", None):
            result["error"] = done.stderr.decode(errors="replace")[:500]
    except (OSError, subprocess.SubprocessError) as exc:
        result["error"] = str(exc)
    return result


if __name__ == "__main__":  # manual check: render an empty wall
    body, summary, count = render_elements({"192.0.2.1", "203.0.113.0/24",
                                            "2001:db8::/32"})
    print(summary, count, file=sys.stderr)
    print(body)
