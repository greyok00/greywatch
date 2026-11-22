"""feeds — pulled threat-intel lists as untrusted input (plan Task 2, LAW-4).

Every pull is capped, hashed, validated; a hostile or failed pull keeps
yesterday's set. apply_verdict() structurally cannot return an allow:
a feed may only contribute a DENY or an annotation. Feed set per the
rebuild design § 7, all keyless.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import pathlib
import urllib.request

PULL_TIMEOUT_S = 5.0
DEFAULT_MAX_BYTES = 20_000_000      # phishing-army alone is ~7 MB compressed-free
LINE_CAP = 512
DEFAULT_MAX_ROWS = 3_000_000

CATEGORIES = ("ads", "trackers", "malware", "phishing", "bad-ip")


class ParseError(ValueError):
    """The body fails its feed's format contract."""


class FeedSpec:
    __slots__ = ("name", "url", "category", "max_bytes", "max_rows",
                 "cadence_s", "parser", "kind", "tier", "curator",
                 "derived_from")

    def __init__(self, name: str, url: str, category: str, max_bytes: int,
                 max_rows: int, cadence_s: int, parser: str,
                 kind: str = "domain", tier: int = 1, curator: str = "",
                 derived_from: tuple = ()):
        self.name = name
        self.url = url
        self.category = category
        self.max_bytes = max_bytes
        self.max_rows = max_rows
        self.cadence_s = cadence_s
        self.parser = parser
        self.kind = kind
        # Web of trust: tier 1 enforces on its own say-so; tier 2 rows are
        # enforced only when an independent source lists them too.
        self.tier = tier
        self.curator = curator or name
        self.derived_from = tuple(derived_from)

    def as_dict(self) -> dict:
        return {"name": self.name, "url": self.url, "category": self.category,
                "max_bytes": self.max_bytes, "max_rows": self.max_rows,
                "cadence_s": self.cadence_s, "parser": self.parser,
                "kind": self.kind, "tier": self.tier,
                "curator": self.curator, "derived_from": self.derived_from}


URLHAUS_HOSTS = "https://urlhaus.abuse.ch/downloads/hostfile/"
FEEDS: dict[str, FeedSpec] = {
    "hagezi-multi-normal": FeedSpec(
        "hagezi-multi-normal",
        # hagezi moved the domains lists under wildcard/<name>-onlydomains.txt
        # (404 upstream since Nov 2026); urlhaus retired its public
        # downloads entirely (410 Gone). Both verified live 2026-11-14.
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/multi-onlydomains.txt",
        "ads", DEFAULT_MAX_BYTES, DEFAULT_MAX_ROWS, 86_400, "domains",
        tier=1, curator="hagezi"),
    "hagezi-tif": FeedSpec(
        "hagezi-tif",
        # Threat Intelligence Feeds, mini dnsmasq variant (tif.mini.txt,
        # ~224k rows / 5.8 MB live 2026-11-21). The full dnsmasq variant
        # (~1M rows) would exceed the dnsmasq render budget; hosts/tif.txt
        # is 404 upstream.
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/dnsmasq/tif.mini.txt",
        "malware", 50_000_000, DEFAULT_MAX_ROWS, 86_400, "dnsmasq",
        tier=1, curator="hagezi"),
    "oisd-small": FeedSpec(
        "oisd-small",
        # domainswild serves the wildcard variant: every line is *.domain
        # (GW-05: the validator used to drop all 62k rows).
        "https://small.oisd.nl/domainswild",
        "ads", DEFAULT_MAX_BYTES, DEFAULT_MAX_ROWS, 86_400, "domains",
        tier=1, curator="oisd"),
    # abuse.ch retired urlhaus's own downloads (410 Gone, Nov 2026); its
    # community successor keeps the malicious-hosts feed current online
    "urlhaus": FeedSpec(
        "urlhaus",
        "https://raw.githubusercontent.com/curbengh/urlhaus-filter/"
        "gh-pages/urlhaus-filter-hosts.txt",
        "malware", 4_000_000, DEFAULT_MAX_ROWS, 3_600, "hosts",
        tier=1, curator="abuse.ch"),
    "stevenblack": FeedSpec(
        "stevenblack",
        # Unified hosts (ads + malware + phishing base, live 2026-11-21).
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "ads", 8_000_000, DEFAULT_MAX_ROWS, 86_400, "hosts",
        tier=1, curator="stevenblack"),
    "onehosts-lite": FeedSpec(
        "onehosts-lite",
        # 1Hosts Lite domains variant — tier 2: corroborating curator only.
        "https://raw.githubusercontent.com/badmojr/1Hosts/main/Lite/domains.txt",
        "ads", 12_000_000, DEFAULT_MAX_ROWS, 86_400, "domains",
        tier=2, curator="1hosts"),
    "phishing-army": FeedSpec(
        "phishing-army",
        "https://phishing.army/download/phishing_army_blocklist_extended.txt",
        "phishing", DEFAULT_MAX_BYTES, DEFAULT_MAX_ROWS, 43_200, "domains",
        tier=1, curator="phishing-army"),
    "openphish": FeedSpec(
        "openphish", "https://openphish.com/feed.txt", "phishing",
        4_000_000, DEFAULT_MAX_ROWS, 43_200, "urls",
        tier=1, curator="openphish"),
    # --- IP intel (firewall layer) -------------------------------------
    "spamhaus-drop": FeedSpec(
        "spamhaus-drop",
        # DROP/EDROP: hijacked netblocks, tab-free bare CIDR list.
        "https://www.spamhaus.org/drop/drop.txt",
        "bad-ip", 1_000_000, DEFAULT_MAX_ROWS, 43_200, "netset",
        kind="ip", tier=1, curator="spamhaus"),
    "cins-army": FeedSpec(
        "cins-army",
        # CINS Army: rogue-datacenter IPs, one bare address per line.
        "https://cinsscore.com/list/ci-badguys.txt",
        "bad-ip", 2_000_000, DEFAULT_MAX_ROWS, 43_200, "netset",
        kind="ip", tier=1, curator="cins"),
    "blocklist-de": FeedSpec(
        "blocklist-de",
        # Aggregate of blocklist.de fail2ban reporters; refreshes fast.
        "https://lists.blocklist.de/lists/all.txt",
        "bad-ip", 2_000_000, DEFAULT_MAX_ROWS, 14_400, "netset",
        kind="ip", tier=1, curator="blocklist.de"),
    "dshield": FeedSpec(
        "dshield",
        # SANS top-20 attacker subnets; tab-separated start/end/prefix.
        "https://www.dshield.org/block.txt",
        "bad-ip", 256_000, DEFAULT_MAX_ROWS, 86_400, "dshield",
        kind="ip", tier=1, curator="dshield"),
    # firehol_level1 is an AGGREGATOR of the tier-1 IP sets above, so it
    # never corroborates their entries (GW-06: registered kind="domain"
    # by accident, which dropped 99.96% of its CIDR rows on the hostname
    # validation path; parser now netset, kind ip).
    "firehol-l1": FeedSpec(
        "firehol-l1",
        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
        "bad-ip", 4_000_000, DEFAULT_MAX_ROWS, 86_400, "netset",
        kind="ip", tier=2, curator="firehol",
        derived_from=("spamhaus-drop", "dshield", "cins-army")),
}

# A destination matched in these categories is a SILENT deny (or card at
# L4 when the chain's heuristics add weight, decided by decide(), never
# by the feed itself): feeds annotate and deny, they never allow.
DENY_CATEGORIES = frozenset({"malware", "phishing", "bad-ip", "ads", "trackers"})


def _valid_host(token: str) -> bool:
    if not token or len(token) > LINE_CAP or "/" in token or " " in token:
        return False
    # IPv6 literals have no dots and must not be smuggled through the
    # hostname label path (which would reject or mangle the colons).
    if ":" in token:
        return _valid_ip(token)
    labels = token.rstrip(".").split(".")
    if len(labels) < 2:
        return False
    # A 4-label all-digit shape is an IPv4 attempt, not a hostname: it
    # must parse as an IP or be dropped, never smuggled in as domain.
    if len(labels) == 4 and all(p.isdigit() for p in labels):
        return _valid_ip(token)
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-_")
    for label in labels:
        low = label.lower()
        if not low or len(low) > 63 or low.startswith("-") or low.endswith("-"):
            return False
        if not set(low) <= allowed:
            return False
    return True


def _valid_ip(token: str) -> bool:
    """IPv4 or IPv6, exactly one address (no prefix, zone or port)."""
    try:
        ipaddress.ip_address(str(token))
    except (TypeError, ValueError):
        return False
    return True


def _clean_domain(token: str) -> str | None:
    """One comment-stripped token or None. Tracks a sub-comment heuristic:
    line may carry a trailing path (openphish URLs) — trimmed by caller."""
    low = token.strip().lower()
    if not low or low.startswith("#") or low.startswith("//"):
        return None
    return low


def _valid_net(token: str) -> bool:
    """A bare address or a CIDR range (host bits tolerated, normalized)."""
    try:
        ipaddress.ip_network(str(token), strict=False)
    except (TypeError, ValueError):
        return False
    return True


def parse(content: str, spec: FeedSpec) -> list[str]:
    """Validated rows only; raises ParseError when the body is not a list
    at all (HTML error pages, binary, absurd lines, absurd row counts),
    or when a sizeable body parses to nothing (GW-07: a format drift used
    to replace a good blocklist with a stub and look ok for days)."""
    if not isinstance(content, str) or not content.strip():
        raise ParseError("body empty or not text")
    stripped = content.lstrip()
    if stripped[:14].lower().startswith("<!doctype html") or \
            stripped[:5].lower().startswith("<html"):
        raise ParseError("body is HTML, not a list")
    rows: list[str] = []
    noncomment = 0
    for line in content.splitlines():
        if len(line) > LINE_CAP:
            raise ParseError(f"line exceeds {LINE_CAP} chars: not a list")
        token = _clean_domain(line)
        if token is None:
            continue
        noncomment += 1
        if spec.parser == "hosts":
            parts = token.split()
            if len(parts) >= 2 and _valid_ip(parts[0]):
                token = parts[1]          # standard hostfile pair
            elif len(parts) == 1:
                token = parts[0]          # bare-domain variant: lenient
            else:
                token = None
        elif spec.parser == "urls":
            token = token.split("/")[0] if "//" not in token else token.split("://", 1)[-1].split("/")[0]
        elif spec.parser == "netset":
            # bare IPv4/IPv6 or CIDR; a trailing annotation (" ; SBL123")
            # is noise after the first whitespace
            parts = token.split()
            token = f"{parts[0]}/{parts[2]}" \
                if spec.kind == "ip" and len(parts) >= 3 and \
                parts[2].isdigit() and _valid_net(f"{parts[0]}/{parts[2]}") \
                else (parts[0] if parts and _valid_net(parts[0]) else None)
        elif spec.parser == "dshield":
            # SANS rows are "start end prefix" tab-separated; the range
            # start plus prefix length IS the CIDR.
            parts = token.split()
            token = f"{parts[0]}/{parts[2]}" \
                if len(parts) >= 3 and _valid_net(f"{parts[0]}/{parts[2]}") \
                else None
        elif spec.parser == "dnsmasq":
            if token.startswith("local=/") and token.endswith("/"):
                token = token[7:-1]
            elif token.startswith("address=/") and token.endswith("/"):
                token = token[9:-1]
            else:
                token = None
        elif spec.parser == "domains":
            # wildcard lists (oisd domainswild) mark every row *.domain
            if token.startswith("*."):
                token = token[2:]
            elif token == "*":
                token = None
        if token is None:
            continue
        # netset/dshield tokens are validated inside their branch by
        # _valid_net (addresses AND CIDRs); the kind=="ip" final check
        # only accepts bare addresses, so it would drop every range.
        if spec.parser in ("netset", "dshield"):
            ok = True
        else:
            ok = _valid_ip(token) if spec.kind == "ip" else _valid_host(token)
        if ok:
            rows.append(token)
            if len(rows) > spec.max_rows:
                raise ParseError(f"row count exceeds cap {spec.max_rows}: not a list")
    if not rows and noncomment >= 50:
        raise ParseError(
            f"{noncomment} non-comment lines parsed to 0 rows: "
            "format does not match this feed's parser")
    return rows


class PullResult:
    __slots__ = ("name", "state", "rows", "sha256", "fetched_at", "reason",
                 "kept_yesterday")

    def __init__(self, name: str, state: str, rows: list[str] | None = None,
                 sha256: str | None = None, fetched_at: float = 0.0,
                 reason: str | None = None, kept_yesterday: bool = False):
        self.name = name
        self.state = state              # ok | rejected | failed
        self.rows = rows or []
        self.sha256 = sha256
        self.fetched_at = fetched_at
        self.reason = reason
        self.kept_yesterday = kept_yesterday


def fetch_one(spec: FeedSpec, now: float, client=None, cache_dir=None) -> PullResult:
    """Pull one feed: byte-capped streaming read, parse, atomic store +
    manifest row. Any failure leaves the previous cached set in place.
    ``client`` stands in for urllib in tests (context manager with read)."""
    if cache_dir is None:
        raise ValueError("cache_dir required")
    cache = pathlib.Path(cache_dir)
    cache.mkdir(parents=True, exist_ok=True)
    manifest_path = cache / "manifest.json"
    manifest = {}
    try:
        manifest = json.loads(manifest_path.read_text())
    except (OSError, ValueError):
        manifest = {}
    opener = client or _default_client
    digest = hashlib.sha256()
    chunks: list[bytes] = []
    size = 0
    try:
        with opener(spec.url, PULL_TIMEOUT_S) as resp:
            while True:
                chunk = resp.read(65_536)
                if not chunk:
                    break
                size += len(chunk)
                if size > spec.max_bytes:
                    result = PullResult(spec.name, "rejected",
                                        reason=(f"size cap {spec.max_bytes} "
                                                f"exceeded ({size} bytes)"),
                                        kept_yesterday=True)
                    _record(manifest, manifest_path, result, spec, now)
                    return result
                digest.update(chunk)
                chunks.append(chunk)   # cap bounds total: <= spec.max_bytes
    except (OSError, ValueError) as exc:
        result = PullResult(spec.name, "failed", reason=str(exc), kept_yesterday=True)
        _record(manifest, manifest_path, result, spec, now)
        return result
    text = b"".join(chunks).decode("utf-8", errors="replace")
    try:
        rows = parse(text, spec)
    except ParseError as exc:
        result = PullResult(spec.name, "rejected", reason=str(exc),
                            kept_yesterday=True)
        _record(manifest, manifest_path, result, spec, now)
        return result
    body = "\n".join(rows) + "\n"
    from status import atomic_replace, ui_gid
    atomic_replace(str(cache / f"{spec.name}.txt"), body, gid=ui_gid())
    result = PullResult(spec.name, "ok", rows=rows,
                        sha256=digest.hexdigest(), fetched_at=now)
    _record(manifest, manifest_path, result, spec, now)
    return result


def _default_client(url: str, timeout: float):
    # dshield and blocklist.de (verified 2026-11-21) 403 the default
    # Python-urllib agent; a named client passes.
    req = urllib.request.Request(
        url, headers={"User-Agent": "greywatch-feeds/0.4 (+blocklist)"})
    return urllib.request.urlopen(req, timeout=timeout)


def _record(manifest: dict, manifest_path: pathlib.Path, result: PullResult,
            spec: FeedSpec, now: float) -> None:
    # Carried minor 9 (M5): a rejection/failure is not a pull — stamping
    # fetched_at=now would read as "fresh" and skip the NEXT lane's
    # cadence (one full cadence lost per outage). Keep yesterday's row's
    # timestamp; only a success stamps fresh.
    pulled_at = now if result.state == "ok" \
        else float((manifest.get(spec.name) or {}).get("fetched_at") or 0)
    row = {"state": result.state, "fetched_at": pulled_at,
           "rows": len(result.rows), "sha256": result.sha256,
           "category": spec.category}
    if result.reason:
        row["error"] = result.reason
    if result.kept_yesterday:
        try:
            body = (manifest_path.parent / f"{spec.name}.txt").read_text()
        except OSError:
            body = ""
        row["rows"] = len([ln for ln in body.splitlines() if ln.strip()])
    manifest[spec.name] = row
    from status import atomic_replace, ui_gid
    atomic_replace(str(manifest_path), json.dumps(manifest, indent=1, sort_keys=True),
                   gid=ui_gid())


def cache_set(cache_dir) -> dict[str, set[str]]:
    """name -> set of rows from the current cache (yesterday's kept set
    when today's pull failed). Domains and IPs land together."""
    out: dict[str, set[str]] = {}
    cache = pathlib.Path(cache_dir)
    for name in FEEDS:
        path = cache / f"{name}.txt"
        try:
            out[name] = {ln.strip().lower() for ln in
                         path.read_text().splitlines() if ln.strip()}
        except OSError:
            out[name] = set()
    return out


def apply_verdict(dest: str, cache_dir) -> tuple[str | None, str | None]:
    """(category, feed_name) when the destination is on any feed; else
    (None, None). Lookup tries the exact host and its parent domains.
    DENY-or-annotation only: there is no allow return by construction."""
    host = (dest or "").strip().lower().rstrip(".")
    if not host:
        return (None, None)
    sets = cache_set(cache_dir)
    if _valid_ip(host):
        # An address has no parent domain; IPv6 has no dots at all, so the
        # old split(".") loop could never reach this exact-match path.
        for name, rows in sets.items():
            if host in rows:
                spec = FEEDS.get(name)
                return (spec.category if spec else "unknown", name)
        return (None, None)
    parts = host.split(".")
    for cut in range(0, len(parts) - 1):
        candidate = ".".join(parts[cut:])
        for name, rows in sets.items():
            if candidate in rows:
                spec = FEEDS.get(name)
                return (spec.category if spec else "unknown", name)
    return (None, None)


def _independent(a: FeedSpec, b: FeedSpec) -> bool:
    """True when b may corroborate a's rows: different curators, and
    neither feed is derived from the other. firehol_level1 republishes
    spamhaus/dshield/cins, so it can never be their second voice."""
    if a.curator == b.curator:
        return False
    return b.name not in a.derived_from and a.name not in b.derived_from


def enforced_rows(cache_dir) -> tuple[dict[str, set[str]], dict]:
    """The web of trust applied to the cache. Returns (rows by feed name,
    report). Tier-1 rows enforce alone. Tier-2 rows enforce only when a
    second, independent feed lists the same row (the aggregator rule:
    different curator, no derived_from link either way). Rows a feed
    holds back are counted, never dropped from its cache file."""
    cache = pathlib.Path(cache_dir)
    cached = cache_set(cache_dir)
    report: dict = {"sources": {}, "totals": {"raw": 0, "enforced": 0,
                                              "held": 0}}
    # index once: row -> tier-1 feed names holding it (domains and IPs
    # share the namespace; a row is corroborated by membership anywhere)
    tier1_index: dict[str, list[str]] = {}
    for name, rows in cached.items():
        spec = FEEDS.get(name)
        if spec is not None and spec.tier == 1:
            for row in rows:
                bucket = tier1_index.get(row)
                if bucket is None:
                    tier1_index[row] = [name]
                else:
                    bucket.append(name)

    out: dict[str, set[str]] = {}
    for name, rows in cached.items():
        spec = FEEDS.get(name)
        if spec is None or spec.tier == 1 or not rows:
            out[name] = set(rows)
            kept = len(rows)
            held = 0
        else:
            kept_set: set[str] = set()
            held = 0
            for row in rows:
                witnesses = tier1_index.get(row, ())
                if any(_independent(spec, FEEDS[w]) for w in witnesses):
                    kept_set.add(row)
                else:
                    held += 1
            out[name] = kept_set
            kept = len(kept_set)
        report["sources"][name] = {
            "tier": spec.tier if spec else 2,
            "curator": spec.curator if spec else name,
            "category": spec.category if spec else "unknown",
            "rows": len(rows), "enforced": kept, "held": held,
            "state": _manifest_state(cache, name)}
        report["totals"]["raw"] += len(rows)
        report["totals"]["enforced"] += kept
        report["totals"]["held"] += held
    return out, report


def _manifest_state(cache: pathlib.Path, name: str) -> str:
    try:
        row = json.loads((cache / "manifest.json").read_text()).get(name) or {}
        return str(row.get("state") or "unknown")
    except (OSError, ValueError):
        return "unknown"
