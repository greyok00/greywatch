"""Web of trust: the vendors and services an ordinary desktop must reach.

The problem this solves (owner 2026-11-13): "find a web of trust and
incorporate it into this as well with the blacklists so they're auto yes
... it eases the burden off the user if they're available and not
accidentally flagged as unsafe."

Two halves, both AUTOMATIC:
  * KNOWN-GOOD - the operating system's own vendors, the major mail/search/
    CDN/AI services, and the distro's update hosts. A connection here is
    expected on any normal machine; stopping to ask is noise, and (as the
    owner found the hard way) guessing wrong locks them out of their mail.
  * KNOWN-BAD - the pulled blocklists. Already automatic; this module only
    makes sure the two never disagree, because a single host in both lists
    is a silent policy fight.

The entries are ADDRESS-FREE on purpose. Vendors rotate IPs constantly and
any hardcoded address goes stale within weeks; matching is by resolved
name and by the ASN-registered ranges the site cache learns, so the trust
follows the vendor rather than a snapshot of it.

This is deliberately a curated, readable list, not a feed: it is the floor
a human can audit in a minute. Everything dangerous still comes from the
signed feeds in core/blocklist.py.
"""
from __future__ import annotations

import pathlib

# --- the known-good floor -------------------------------------------------
# Grouped so an owner can strike out a whole vendor in one line. Names are
# suffix-matched ("*.live.com" also covers "login.live.com"), so a vendor
# entry is one string rather than a hundred hostnames.
KNOWN_GOOD: dict[str, tuple[str, ...]] = {
    "microsoft / mail": (
        "microsoft.com", "*.microsoft.com", "live.com", "*.live.com",
        "outlook.com", "*.outlook.com", "office.com", "*.office.com",
        "office365.com", "*.office365.com", "microsoftonline.com",
        "*.microsoftonline.com", "windows.net", "*.windows.net",
        "azure.com", "*.azure.com", "msftncsi.com", "*.msftncsi.com",
        "windowsupdate.com", "*.windowsupdate.com",
        "hotmail.com", "*.hotmail.com", "msn.com", "*.msn.com",
        "bing.com", "*.bing.com", "skype.com", "*.skype.com",
        "sharepoint.com", "*.sharepoint.com",
    ),
    "google": (
        "google.com", "*.google.com", "googleapis.com", "*.googleapis.com",
        "gstatic.com", "*.gstatic.com", "googleusercontent.com",
        "*.googleusercontent.com", "googlevideo.com", "*.googlevideo.com",
        "youtube.com", "*.youtube.com", "ytimg.com", "*.ytimg.com",
        "ggpht.com", "*.ggpht.com", "gmail.com", "*.gmail.com",
        "android.com", "*.android.com",
    ),
    "apple": (
        "apple.com", "*.apple.com", "icloud.com", "*.icloud.com",
        "mzstatic.com", "*.mzstatic.com", "cdn-apple.com",
        "*.cdn-apple.com",
    ),
    "mozilla / firefox": (
        "mozilla.org", "*.mozilla.org", "mozilla.net", "*.mozilla.net",
        "mozilla.com", "*.mozilla.com", "firefox.com", "*.firefox.com",
    ),
    "cloudflare / big cdn": (
        "cloudflare.com", "*.cloudflare.com", "cloudflare-dns.com",
        "*.cloudflare-dns.com", "fastly.com", "*.fastly.com",
        "akamai.net", "*.akamai.net", "akamaized.net", "*.akamaized.net",
        "amazonaws.com", "*.amazonaws.com", "cloudfront.net",
        "*.cloudfront.net",
    ),
    "code / package / dev": (
        "github.com", "*.github.com", "githubusercontent.com",
        "*.githubusercontent.com", "githubassets.com",
        "*.githubassets.com", "gitlab.com", "*.gitlab.com",
        "pypi.org", "*.pypi.org", "pythonhosted.org", "*.pythonhosted.org",
        "npmjs.org", "*.npmjs.org", "npmjs.com", "*.npmjs.com",
        "crates.io", "*.crates.io", "debian.org", "*.debian.org",
        "ubuntu.com", "*.ubuntu.com", "canonical.com", "*.canonical.com",
        "archlinux.org", "*.archlinux.org", "fedoraproject.org",
        "*.fedoraproject.org", "kernel.org", "*.kernel.org",
    ),
    "ai services": (
        "openai.com", "*.openai.com", "anthropic.com", "*.anthropic.com",
        "claude.ai", "*.claude.ai", "huggingface.co", "*.huggingface.co",
    ),
    "dns / ntp / connectivity checks": (
        "quad9.net", "*.quad9.net", "cloudflare-dns.com",
        "one.one.one.one",
    ),
}


def known_good_entries() -> set[str]:
    """Every known-good suffix, flat."""
    out: set[str] = set()
    for group in KNOWN_GOOD.values():
        out.update(group)
    return out


def groups() -> dict[str, tuple[str, ...]]:
    return dict(KNOWN_GOOD)


def is_known_good(host: str) -> bool:
    """True when `host` falls under a curated vendor suffix.

    Suffix matching, not substring: "notgoogle.com" must not match
    "google.com", which is why the comparison is on label boundaries.
    """
    h = str(host or "").strip().lower().rstrip(".")
    if not h:
        return False
    for entry in known_good_entries():
        e = entry.lower()
        if e.startswith("*."):
            base = e[2:]
            if h == base or h.endswith("." + base):
                return True
        elif h == e or h.endswith("." + e):
            return True
    return False


def apply_to(trust_list) -> int:
    """Seed a TrustList with the known-good floor. Returns how many were new.

    Called at install time and by the daemon's first start, so a fresh box
    does not interrogate the owner about their own mail server. Never
    removes anything: an owner who deliberately auto-blocked a vendor keeps
    that block (the block list wins in TrustList.decide), and this function
    must not silently re-allow what they refused.
    """
    before = set(trust_list.allow)
    trust_list.allow.update(known_good_entries())
    new = len(trust_list.allow - before)
    if new:
        trust_list.save()
    return new


def conflicts(trust_list) -> list[str]:
    """Entries present in BOTH auto-allow and auto-block.

    A host in both lists is a silent policy fight; TrustList.decide picks
    the block, so the allow entry is dead weight that reads like permission
    the owner granted. Surfacing it is the whole point of the trust CLI.
    """
    return sorted(set(trust_list.allow) & set(trust_list.block))
