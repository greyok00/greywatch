"""The network analytics store (owner 2026-11-15: SiteGuard-analytics
style): every device this machine has seen, fingerprinted, every IP with
what flagged it, in one derived file with provenance.

Built FROM the app's own lanes (arpwatch events, netwatch rows, the
blocked-IP ledger, psad/fail2ban rows in the ledger) + the intel feeds
for reputation; nothing here scans the network itself. OUI fingerprints
carry a small embedded map of common vendors and label the rest
honestly.
"""
from __future__ import annotations

import datetime as _dt
import ipaddress
import json
import pathlib
import re
import sys

_IP_TOKEN = re.compile(
    r"\b(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f]*:[0-9A-Fa-f:]+)\b")


def _addresses(text: str) -> list[str]:
    out = []
    for token in _IP_TOKEN.findall(str(text or "")):
        token = token.strip("[]")
        try:
            ipaddress.ip_address(token)
        except ValueError:
            continue
        out.append(token)
    return out

# A small embedded OUI map: the vendors a home/lab network actually has.
# Full lookup tables are data, not code: the report labels unknown MACs
# "vendor unknown" instead of pretending.
OUI = {
    "00:1A:2B": "Ayecom", "00:03:93": "Apple", "AC:DE:48": "Apple",
    "F0:18:98": "Apple", "A4:83:E7": "Apple", "DC:A6:32": "Raspberry Pi",
    "B8:27:EB": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
    "00:50:56": "VMware", "00:0C:29": "VMware", "00:1C:42": "Parallels",
    "08:00:27": "Oracle VirtualBox", "3C:22:FB": "Intel",
    "7C:D1:C3": "Intel", "94:E6:F8": "Intel", "FC:AA:14": "Intel",
    "00:14:22": "Dell", "F8:BC:12": "ASUSTek", "2C:4D:54": "ELTEX",
    "18:C0:4D": "Wistron", "9C:B6:D0": "Rivet Networks",
    "E8:6A:64": "Intel", "3C:5A:B4": "Google", "F4:F5:D8": "Google",
    "54:60:09": "Hewlett Packard", "44:85:00": "Hewlett Packard",
}


def _now_stamp() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


def _vendor(mac: str) -> str:
    return OUI.get(mac.upper()[:8], "vendor unknown")


def _rows(data_dir: pathlib.Path, limit: int = 4000):
    # GW-01: this used to call events_mod.read_events() — a function that
    # lives in greywatch_daemon, not events — and the bare except returned
    # [], so every build saw zero events and the Network page stayed
    # empty forever. Catch only the expected read failure; anything else
    # is named on stderr, never silently swallowed.
    from greywatch_daemon import read_events
    try:
        return read_events(data_dir / "events.jsonl", limit=limit)
    except OSError:
        return []
    except Exception as exc:             # noqa: BLE001
        print(f"netmon: event reader failed: {exc!r}", file=sys.stderr)
        return []


def _dat_devices(dat_dir: str | None = None):
    """arpwatch's persistent fingerprint store: /var/lib/arpwatch/*.dat,
    one 'mac\\tip\\tepoch\\ttype\\tiface' row per device ever seen. The
    'new station' journal events fire once per database lifetime, so the
    device list starved without these (GW-04). Returns touch_device
    material: (mac, ip, when_iso, what)."""
    dat_dir = dat_dir or "/var/lib/arpwatch"
    try:
        paths = sorted(pathlib.Path(dat_dir).glob("*.dat"))
    except OSError:
        return []
    out = []
    for path in paths:
        try:
            body = path.read_text(errors="replace")
        except OSError:
            continue
        for line in body.splitlines():
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            mac, ip, epoch = parts[0].strip(), parts[1].strip(), parts[2].strip()
            if not re.fullmatch(r"[0-9A-Fa-f:]{17}", mac):
                continue
            try:
                when = _dt.datetime.fromtimestamp(
                    int(epoch), _dt.timezone.utc).isoformat(timespec="seconds")
            except (ValueError, OSError, OverflowError):
                when = None
            out.append((mac, ip, when,
                        f"arpwatch fingerprint ({path.stem})"))
    return out


def build(data_dir=None, arpwatch_dir: str | None = None) -> dict:
    """One build pass over the app's own lane records."""
    try:
        import gwpaths
        data_dir = data_dir or gwpaths.data_dir()
    except Exception:                    # noqa: BLE001
        data_dir = pathlib.Path("/var/lib/greywatch")
    data_dir = pathlib.Path(data_dir)
    devices: dict = {}
    ips: dict = {}

    def touch_ip(ip, *, by=None, when=None, what=None):
        if not ip:
            return
        row = ips.setdefault(ip, {"first_seen": when, "last_seen": None,
                                  "flagged_by": [], "what": []})
        row["last_seen"] = when or row["last_seen"] or _now_stamp()
        row["first_seen"] = when or row["first_seen"]
        if by and by not in row["flagged_by"]:
            row["flagged_by"].append(by)
        if what:
            row["what"].append({"when": when, "what": what})

    def touch_device(mac, ip=None, when=None, what=None):
        if not mac:
            return
        row = devices.setdefault(mac, {
            "vendor": _vendor(mac), "first_seen": None, "last_seen": None,
            "ips": [], "what": []})
        if ip and ip not in row["ips"]:
            row["ips"].append(ip)
        row["last_seen"] = when or row["last_seen"] or _now_stamp()
        row["first_seen"] = when or row["first_seen"]
        if what:
            row["what"].append({"when": when, "what": what})
        if ip:
            touch_ip(ip, by="arp", when=when, what=what)

    blocked = []
    try:
        snap = json.loads((data_dir / "status.json").read_text(
            encoding="utf-8"))
        blocked = (snap.get("defense") or {}).get("blocked") or []
    except (OSError, ValueError):
        blocked = []
    for row in blocked:
        ip = str(row.get("ip") or "")
        touch_ip(ip, by="nft-block", when=row.get("ts"),
                 what=row.get("reason") or "blocked")

    for ev in _rows(data_dir):
        tool = str(ev.get("from_tool") or "")
        text = str(ev.get("text") or "")
        when = ev.get("ts")
        if tool == "arpwatch" and ("new station" in text
                                   or "changed ethernet" in text):
            # "new station <mac> (<ip>)" arpwatch's own report shape
            import re
            m = re.search(r"([0-9A-Fa-f:]{17})\s*\(?([0-9.]{7,15})?", text)
            if m:
                touch_device(m.group(1), m.group(2), when, text[:120])
        elif tool == "net-watch":
            touch_ip(text[:64], by="net-watch", when=when, what=text[:120])
        elif tool in ("psad", "fail2ban"):
            for ip in _addresses(text):
                touch_ip(ip, by=tool, when=when, what=text[:120])
                touch_device("unknown-mac", ip, when, f"{tool} flagged the ip")

    # the persistent fingerprint store: devices the ledger never saw
    # because "new station" fires once per arpwatch database lifetime
    for mac, ip, when, what in _dat_devices(arpwatch_dir):
        touch_device(mac, ip, when, what)

    # the intel feeds: which flagged IPs are on a known bad list.
    # GW-09: this was exact-string regex against the raw file, so a CIDR
    # row could never match a concrete address. Rows are split once into
    # exact-address sets and networks; membership does the matching.
    try:
        import feeds as feeds_mod
        feed_dir = data_dir / "feeds"
        per_feed = {}
        for name, spec in feeds_mod.FEEDS.items():
            try:
                rows = [ln.strip().lower() for ln
                        in (feed_dir / f"{spec.name}.txt")
                        .read_text().splitlines() if ln.strip()]
            except OSError:
                continue
            exact = {r for r in rows if feeds_mod._valid_ip(r)}
            nets = []
            for r in rows:
                if "/" in r:
                    try:
                        nets.append(ipaddress.ip_network(r, strict=False))
                    except ValueError:
                        continue
            per_feed[name] = (exact, nets)
        for ip in list(ips):
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            for name, (exact, nets) in per_feed.items():
                if str(addr) in exact or any(addr in n for n in nets):
                    touch_ip(ip, by=f"intel:{name}", when=_now_stamp(),
                             what=f"on the {name} feed")
    except Exception as exc:             # noqa: BLE001
        print(f"netmon: intel pass skipped: {exc!r}", file=sys.stderr)

    return {
        "version": 1,
        "built_at": _now_stamp(),
        "devices": devices,
        "ips": ips,
        "counts": {"devices": len(devices), "ips": len(ips),
                   "flagged": len([1 for i in ips.values()
                                   if i["flagged_by"]])},
    }


def persist(report: dict, data_dir=None) -> pathlib.Path:
    try:
        import gwpaths
        data_dir = data_dir or gwpaths.data_dir()
    except Exception:                    # noqa: BLE001
        data_dir = pathlib.Path("/var/lib/greywatch")
    out = pathlib.Path(data_dir) / "network-analytics.json"
    from status import atomic_replace, ui_gid
    atomic_replace(str(out),
                   json.dumps(report, indent=1, sort_keys=True) + "\n",
                   gid=ui_gid())
    return out


def human(report: dict) -> str:
    c = report["counts"]
    lines = [f"network analytics: {c['devices']} device(s), "
             f"{c['ips']} ip(s), {c['flagged']} flagged by a lane or feed"]
    for ip, row in list(report["ips"].items()):
        if row["flagged_by"]:
            lines.append(f"  {ip:<16} flagged by "
                         f"{', '.join(row['flagged_by'])}  "
                         f"(last: {(row['last_seen'] or '')[:19]})")
    for mac, row in list(report["devices"].items())[:10]:
        who = row["vendor"]
        lines.append(f"  {mac:<18} {who:<22} "
                     f"{', '.join(row['ips']) or '-':<16} "
                     f"first {str(row['first_seen'] or '')[:10]}, "
                     f"last {str(row['last_seen'] or '')[:10]}")
    return "\n".join(lines)
