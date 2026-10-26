# HELP/tools — per-tool log-format index

The LIVE truth for every parser is `~/greywatch/parsers.py` (each tool a
`parse_<name>` function, real formats, malformed → malformed.log) with
regression fixtures in `tests/fixtures/`. Before writing/changing a parser,
consult: (1) parsers.py's existing function for that tool, (2) its fixtures,
(3) the upstream doc listed here when needed.

roster (17, registry.json): responderd (own log), tetragon (eBPF jsonl
events /etc/tetragon), yara-watch + yara-tmp-scan (scan logs), clamav +
freshclam, fail2ban (its log), ufw ([UFW BLOCK] kernel lines + the
apparmor-reroute quirk in daemon consume()), appfw (data/appfw/events.jsonl
engine-mirror lines), auditd, arpwatch (journal), aide, apparmor, lynis,
rkhunter, net-watch (data/netwatch-events.jsonl `netwatch SEV text` lines —
the in-daemon IDS), cve-updater (cve-cache.json), freshclam.
Upstream one-doc-per-tool man pages: fetch on first touch of a given
parser; do not bulk-fetch docs for parsers that already pass fixtures.