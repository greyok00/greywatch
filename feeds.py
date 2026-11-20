"""feeds — pulled threat-intel lists as untrusted input (plan Task 2, LAW-4).

Every pull is capped, hashed, validated; a hostile or failed pull keeps
yesterday's set. apply_verdict() structurally cannot return an allow:
a feed may only contribute a DENY or an annotation. Feed set per the
rebuild design § 7, all keyless.
"""
from __future__ import annotations

import hashlib
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
                 "cadence_s", "parser", "kind")

    def __init__(self, name: str, url: str, category: str, max_bytes: int,
                 max_rows: int, cadence_s: int, parser: str,
                 kind: str = "domain"):
        self.name = name
        self.url = url
        self.category = category
        self.max_bytes = max_bytes
        self.max_rows = max_rows
        self.cadence_s = cadence_s
        self.parser = parser
        self.kind = kind

    def as_dict(self) -> dict:
        return {"name": self.name, "url": self.url, "category": self.category,
                "max_bytes": self.max_bytes, "max_rows": self.max_rows,
                "cadence_s": self.cadence_s, "parser": self.parser,
                "kind": self.kind}


URLHAUS_HOSTS = "https://urlhaus.abuse.ch/downloads/hostfile/"
FEEDS: dict[str, FeedSpec] = {
    "hagezi-multi-normal": FeedSpec(
        "hagezi-multi-normal",
        # hagezi moved the domains lists under wildcard/<name>-onlydomains.txt
        # (404 upstream since Nov 2026); urlhaus retired its public
        # downloads entirely (410 Gone). Both verified live 2026-11-14.
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/multi-onlydomains.txt",
        "ads", DEFAULT_MAX_BYTES, DEFAULT_MAX_ROWS, 86_400, "domains"),
    "oisd-small": FeedSpec(
        "oisd-small",
        "https://small.oisd.nl/domainswild",
        "ads", DEFAULT_MAX_BYTES, DEFAULT_MAX_ROWS, 86_400, "domains"),
    # abuse.ch retired urlhaus's own downloads (410 Gone, Nov 2026); its
    # community successor keeps the malicious-hosts feed current online
    "urlhaus": FeedSpec(
        "urlhaus",
        "https://raw.githubusercontent.com/curbengh/urlhaus-filter/"
        "gh-pages/urlhaus-filter-hosts.txt",
        "malware", 4_000_000, DEFAULT_MAX_ROWS, 3_600, "hosts"),
    "phishing-army": FeedSpec(
        "phishing-army",
        "https://phishing.army/download/phishing_army_blocklist_extended.txt",
        "phishing", DEFAULT_MAX_BYTES, DEFAULT_MAX_ROWS, 43_200, "domains"),
    "openphish": FeedSpec(
        "openphish", "https://openphish.com/feed.txt", "phishing",
        4_000_000, DEFAULT_MAX_ROWS, 43_200, "urls"),
    "firehol-l1": FeedSpec(
        "firehol-l1",
        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
        "bad-ip", 4_000_000, DEFAULT_MAX_ROWS, 86_400, "ips"),
}

# A destination matched in these categories is a SILENT deny (or card at
# L4 when the chain's heuristics add weight, decided by decide(), never
# by the feed itself): feeds annotate and deny, they never allow.
DENY_CATEGORIES = frozenset({"malware", "phishing", "bad-ip", "ads", "trackers"})


def _valid_host(token: str) -> bool:
    if not token or len(token) > LINE_CAP or "/" in token or " " in token:
        return False
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
    parts = token.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        if not 0 <= int(part) <= 255:
            return False
        if len(part) > 1 and part.startswith("0"):
            return False
    return True


def _clean_domain(token: str) -> str | None:
    """One comment-stripped token or None. Tracks a sub-comment heuristic:
    line may carry a trailing path (openphish URLs) — trimmed by caller."""
    low = token.strip().lower()
    if not low or low.startswith("#") or low.startswith("//"):
        return None
    return low


def parse(content: str, spec: FeedSpec) -> list[str]:
    """Validated rows only; raises ParseError when the body is not a list
    at all (HTML error pages, binary, absurd lines, absurd row counts)."""
    if not isinstance(content, str) or not content.strip():
        raise ParseError("body empty or not text")
    stripped = content.lstrip()
    if stripped[:14].lower().startswith("<!doctype html") or \
            stripped[:5].lower().startswith("<html"):
        raise ParseError("body is HTML, not a list")
    rows: list[str] = []
    for line in content.splitlines():
        if len(line) > LINE_CAP:
            raise ParseError(f"line exceeds {LINE_CAP} chars: not a list")
        token = _clean_domain(line)
        if token is None:
            continue
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
        if token is None:
            continue
        ok = _valid_ip(token) if spec.kind == "ip" else _valid_host(token)
        if ok:
            rows.append(token)
            if len(rows) > spec.max_rows:
                raise ParseError(f"row count exceeds cap {spec.max_rows}: not a list")
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
    from status import atomic_replace
    atomic_replace(str(cache / f"{spec.name}.txt"), body)
    result = PullResult(spec.name, "ok", rows=rows,
                        sha256=digest.hexdigest(), fetched_at=now)
    _record(manifest, manifest_path, result, spec, now)
    return result


def _default_client(url: str, timeout: float):
    return urllib.request.urlopen(url, timeout=timeout)


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
    from status import atomic_replace
    atomic_replace(str(manifest_path), json.dumps(manifest, indent=1, sort_keys=True))


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
    parts = host.split(".")
    for cut in range(0, len(parts) - 1):
        candidate = ".".join(parts[cut:])
        for name, rows in sets.items():
            if candidate in rows:
                spec = FEEDS.get(name)
                return (spec.category if spec else "unknown", name)
        if _valid_ip(host):
            break             # IPs don't have parents
    return (None, None)
