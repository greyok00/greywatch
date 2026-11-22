# Changelog

GreyWatch follows a locked family version (`0.4.5.x`): the first two
components are the shipped product line, the third is frozen while the
family remains current, and only the last decimal moves with each patch
wave. The authoritative version lives in `pyproject.toml` alone —
`cli.py --version` and every packaging script read it from there.

## 0.4.5.7 — 2026-11-21

Fix wave from the external audit, plus two repair commits that rode in
the same window after 0.4.5.6.

- CVE unit deployment no longer follows a pre-planted symlink:
  `sync-to-system.sh` wrote the substituted `greywatch-cve.service`
  unit to a fixed `/tmp` name as root before installing it, so any
  local user could truncate an arbitrary root-owned file by planting
  `/tmp/greywatch-cve.service` as a symlink. The unit is now staged in
  a private 0700 `mktemp` directory (the same class the repo's own
  `appfw/ruleset.py` already fixed).
- The deb package now ships the CLI: nothing under `/usr/bin` existed
  on a deb install even though the README Quick start ends with
  `gw status`. `packaging/build-deb.sh` installs `/usr/bin/gw` and
  `/usr/bin/greywatch` shims that exec `/opt/greywatch/cli.py`, so the
  documented commands work out of the box.
- Long-lived-daemon memory bounds: `notifyd._dedup_at` grew one entry
  per distinct alert text forever, and `netwatch._deny_hits` /
  `_last_cluster` grew one key per distinct denied host forever. Both
  now evict through the existing bound/sweep discipline their sister
  tables already used.
- Arpwatch timestamps stay current: the syslog-style parser stamped
  month/day events with a frozen default year, so from 2027 onward
  every arpwatch event would sort one year into the past. The year is
  now derived at parse time from the current UTC date.
- Ledger appends separate on a torn tail: the pending-ask writer reads
  the ledger's last byte through a read-only fd (an `O_APPEND`
  descriptor cannot be read) so the boot pass never welds the first
  appended event onto a seeded line that ends without a newline.
- Test portability: the battery no longer depends on the ambient
  environment for the cases that exercise battery-failure reporting.

## 0.4.5.6 — 2026-11-21

Fresh public snapshot (commit `ff28264`).

- Web of trust: twelve curated threat feeds tiered by curator
  independence; a tier-2 row only enforces when an independent second
  source names the same host or netblock.
- Two enforcement layers (dnsmasq blocklist for the local resolver, a
  dedicated nftables table for listed netblocks) re-applied at boot,
  with a per-source feed report of enforced and held counts.
- Passive host-local inbound sensor (netguard): sweep alerts on packets
  addressed to this machine, with temporary blocks for external
  sources only.
- Network analytics gain arpwatch fingerprint baselines and
  subnet-aware intel matching; Security Center and tool tables became
  one-click with honest empty-state copy.
- Lane-written state unified to 0640 root:grey.

Earlier releases shipped as tagged snapshots before this changelog
existed; their history lives in the commit log.
