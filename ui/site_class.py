"""What is this site? A deterministic, table-driven guess.

Names first (a host that calls itself amazonaws is Amazon's cloud whatever
port it uses), then well-known ports, then an honest "unrecognized". This
never claims more than the evidence supports.
"""
from __future__ import annotations

NAME_FAMILIES = (
    ("amazonaws", "Amazon cloud"),
    ("cloudfront", "content delivery"),
    ("akamai", "content delivery"),
    ("cloudflare", "content delivery"),
    ("googleapis", "Google service"),
    ("gstatic", "Google service"),
    ("google", "Google service"),
    ("windowsupdate", "Microsoft service"),
    ("microsoft", "Microsoft service"),
    ("nflxvideo", "video streaming"),
    ("netflix", "video streaming"),
    ("spotify", "music streaming"),
    ("steam", "game platform"),
    ("github", "code hosting"),
    ("gitlab", "code hosting"),
    ("ubuntu", "software updates"),
    ("debian", "software updates"),
    ("fedora", "software updates"),
    ("archlinux", "software updates"),
    ("mozilla", "browser services"),
    ("apple", "Apple service"),
)

PORT_SERVICES = {
    443: "secure web", 80: "web", 53: "name lookup (DNS)",
    25: "mail", 587: "mail", 22: "remote login (SSH)",
    3306: "database", 5432: "database", 1194: "VPN", 51820: "VPN",
}


def classify(name: str = "", port: int | None = None) -> str:
    low = (name or "").lower()
    for token, label in NAME_FAMILIES:
        if token in low:
            return label
    try:
        wanted = int(port) if port is not None else None
    except (TypeError, ValueError):
        wanted = None
    if wanted in PORT_SERVICES:
        return PORT_SERVICES[wanted]
    return "unrecognized service — treat with care"
