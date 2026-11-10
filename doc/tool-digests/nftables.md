# nftables — the firewall stack

Source: man page nft(8), digested through the greysearch RAG ingester into gw-tools.

WHAT IT IS: The kernel packet filter and the lane GreyWatch enforces
through (with nfq_worker for decision enforcement). Rules are keyed
program+target for app-level allows/blocks and address-level for psad
blocks. `nft list ruleset` shows the live state; GreyWatch writes rules
through its polkit apply lane so the UI buttons are the terminal for
this, not a second shell.

WHAT ITS EVENTS MEAN: blocked = a rule denied traffic (the address table
on Firewall); allowed-saved = a permanent rule now permits the program.

HEURISTICS:
- Every Allow/Block on a row writes a PERMANENT rule, named for its
  reason; "allow chrome" states exactly what got allowed.
- Before changing rules from an advisory, verify the row's cause
  (probes vs brute force vs unknown program) — the wall verdict strip
  shows the counts, the rows show the reasons.
- A missing nft chain = Firewall-page critical state (psad calls it too);
  rebuild the chain from the tool card, never by hand-editing mid-session.
- Unblock removes the block rule the same way it was added — the row says
  "Unblocked 10.0.0.7 — rule removed", not a generic success.
