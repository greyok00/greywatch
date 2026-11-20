# psad — Port Scan Attack Detector

Source: man page psad(8), digested through the greysearch RAG ingester into gw-tools.

WHAT IT IS: A daemon that reads firewall (iptables/nftables) logs, detects
port scans and suspect traffic, assigns each source a danger level 1-5
(5 highest), and can auto-block. Danger levels rise with signature matches
in /etc/psad/signatures, with IP danger-level adjustments from
/etc/psad/auto_dl (which raises, lowers, or ignores danger levels for
listed addresses), the
PORT_RANGE_SCAN_THRESHOLD gap, and whether scans are allowed to timeout
(SCAN_TIMEOUT).

KEY COMMANDS: `psad` (daemon start/restart via the app), `psad -S` status
summary, `psad --fw-analyze` and `psad --fw-dump` to verify and inspect
the firewall chain (fwcheck_psad is a helper script, not a flag),
`psad -D, --Dump-conf`.
Config lives in /etc/psad/psad.conf; AUTO_BLOCK / ALERT levels control
actions; GreyWatch also exposes `Alert level` and `auto-block` as dock
knobs that write that config through the polkit apply lane.

WHAT ITS WARNINGS MEAN: events in the log are probe/scan observations
against firewall policy; GreyWatch republishes notable ones as
`scan-warning` findings with a suggested action.

HEURISTICS:
- A resolved probe (block or unblock chosen) keys on (rule, source IP) —
  it must not refire every cycle for the same address.
- "Blocked address" rows resolve with Unblock on the row; the wall verdict
  strip is the one place "am I covered" is answered.
- If the firewall chain goes missing, psad reports it: treat as
  Firewall-page critical, not an Activity-log footnote.
- Scans from the local LAN are usually printers/new devices, not
  attackers — verify the MAC/device before hard-blocking.
