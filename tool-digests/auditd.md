# auditd — Auditd (Linux audit log)

Source: man page auditd(8) + the GreyWatch auditd lane, digested through the greysearch RAG ingester into gw-tools.

WHAT IT IS: The kernel's audit trail. Auditd records security-relevant
kernel events you configured rules for: file watches on /etc, identity
changes (setuid, group changes), logins, and binary executions under
watched paths. It is log-based and rule-driven — silence means no rule
fired, not that nothing happened.

WHAT ITS WARNINGS MEAN: an audit row carries a type (SYSCALL, USER_AUTH,
WATCH) and fields (comm, exe, key). WATCH rows fire because a rule
keyed that path — after a legitimate edit the same row fires again
until the rule is retired; that is watching, not attacking. Auth rows
are the login story of the machine.

HEURISTICS:
- Watch rows on /etc right after your own package upgrades are expected:
  verify the change is yours, then let the row age out; re-baselining is
  not part of auequiv — the row IS the record.
- USER_AUTH failures repeating from one address: that is a brute force
  pattern — the fail2ban lane is where the ban lands, auditd is where
  the evidence lives.
- Audit rules that match nothing for weeks may have drifted from the
  current system layout; retire dead rules instead of widening them.
- The audit log can be heavy: caps keep the ledger bounded, and the
  rate-limit honesty line trips when the source floods — the dashboard
  will say DEGRADED, not hide the flood.
