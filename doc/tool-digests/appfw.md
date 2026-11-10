# appfw — GreyWatch application firewall (internal)

No man page; curated from the GreyWatch fix-wave records, stored in gw-tools.

WHAT IT IS: The application firewall inside GreyWatch. It watches program
executions and network binds/connects from /proc events, publishes
decisions (allow/block asks) into decisions.jsonl, and enforces through
the nft lane with an nfq_worker at /opt/greywatch/appfw/bin.

WHAT ITS EVENTS MEAN: "unknown program" = a binary executed or connected
without an existing rule; "port bind" = a program wants to listen.
Decisions wait in the gate until decided on their one row — Keep /
Delete / Restore or Allow rule / Block rule.

HEURISTICS:
- Allow only binaries you recognize (browser, updater, office suite);
  Block unknown executables from /tmp, /var/tmp, and user Downloads.
- Malware is DELETED cleanly: the Delete now lane removes persistence
  hooks and records path+hash in the ledger; quarantine is the undo.
- If a resolved row repeats, the resolution keyed the wrong subject: fix
  the key to (rule, subject), never the event id.
- Junk pending specs (title "?" or ts) mean a corrupted decisions file:
  rekey and dedupe instead of showing junk to the owner.
- The ledger trims hourly with caps pinned in tests; never disable the
  trim to "keep evidence" — the ledger keeps what the caps allow.
