"""The block reviewer: audits blocked addresses and QUESTIONS, never fixes.

The owner's directive (2026-11-06): "a block reviewer where it'll correct my
decisions if it finds that i accidentally blocked something i shouldn't
have. it should question, not auto fix."  The block reviewer therefore has two
hard properties baked in: it produces question specs for blocks that
match the baselines (an address on the house's own network, or a
content-delivery network that ordinary browsing arrives over), and no
function in this module touches the firewall or the ledger. The only way
a block moves after a block reviewer question is the keeper's own choice in
the card, which runs a real helper.

The ranges below are baselines: best-effort headline prefixes of the big
content networks, correct when written, drifting over time. They are
deliberately conservative: when unsure, the block reviewer asks nothing and
treats the address as a scanner it has no reason to doubt a block for.
"""
from __future__ import annotations

import hashlib
import ipaddress

OWN_RANGES = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
              "127.0.0.0/8", "169.254.0.0/16", "fe80::/10", "::1/128")

# Content-delivery networks: shared edge addresses that legitimate sites
# round-robin over. Blocking one usually means one or more ordinary sites
# stop loading. Headline prefixes only.
CDN_RANGES = (
    # cloudflare
    "104.16.0.0/13", "172.64.0.0/13", "162.158.0.0/15",
    # fastly
    "23.235.32.0/20", "146.75.0.0/16", "151.101.0.0/16",
    # akamai
    "23.32.0.0/11", "95.100.0.0/15", "96.6.0.0/15",
    # amazon cloudfront
    "13.32.0.0/12", "18.64.0.0/13", "52.84.0.0/15", "99.86.0.0/16",
    "143.204.0.0/16", "205.251.200.0/21",
    # google edge fronts
    "74.125.0.0/16", "142.250.0.0/15",
)

_OWN_NETS = [ipaddress.ip_network(r) for r in OWN_RANGES]
_CDN_NETS = [ipaddress.ip_network(r) for r in CDN_RANGES]


def classify(ip: str) -> dict:
    """Reads one address against the baselines.

    Returns {"cls": own-infra|cdn|datacenter, "why": plain sentence}.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"cls": "datacenter",
                "why": "not a valid address; treated as hostile"}
    for net in _OWN_NETS:
        if addr in net:
            return {"cls": "own-infra",
                    "why": "this address belongs to the house's own "
                           "network range"}
    for net in _CDN_NETS:
        if addr in net:
            return {"cls": "cdn",
                    "why": "this address sits in a content-delivery range "
                           "ordinary websites are served from"}
    return {"cls": "datacenter",
            "why": "nothing about this address matches the house or the "
                   "big content networks"}


def review_block(ip: str, reason: str = "") -> dict | None:
    """A QUESTION card for blocks that smell accidental, or None.

    None is the common case: psad only reports danger-level 5 attackers,
    so far away addresses are blocked for a reason and the block reviewer has
    nothing to challenge. House addresses and content networks get one
    polite ask, phrased so the answer runs a helper either way.
    """
    verdict = classify(ip)
    if verdict["cls"] == "datacenter":
        return None
    if verdict["cls"] == "own-infra":
        subject = (f"{ip} sits on this house's own network and is blocked")
        question = ("Keep blocking an address from your own home, or lift "
                    "it? I only ever ask; the choice is yours.")
    else:
        subject = f"{ip} belongs to a content network and is blocked"
        question = ("Blocking one of these can silently stop ordinary "
                    "sites loading. Keep the block, or lift it?")
    digest = hashlib.md5(ip.encode()).hexdigest()[:6]
    spec = {
        "id": f"block-reviewer:{digest}",
        "eyebrow": "Block Reviewer check",
        "subject": subject,
        "question": question,
        "options": [
            {"id": "keep", "label": "Keep blocking", "tone": "primary",
             "helper": "block-review", "args": [ip, "keep"]},
            {"id": "lift", "label": "Lift the block", "tone": "neutral",
             "helper": "lift-block", "args": [ip]},
        ],
    }
    if reason:
        spec["detail"] = (f"reason on record: {reason} - {verdict['why']}")
    return spec
