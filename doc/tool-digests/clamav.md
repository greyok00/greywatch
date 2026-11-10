# clamav — ClamAV / clamd anti-virus

Source: man page clamd(8) + the scanner command lane, digested through the greysearch RAG ingester into gw-tools.

WHAT IT IS: The signature anti-virus. clamd is the resident daemon with a
signature database it refreshes (freshclam); clamscan is the on-demand
scanner GreyWatch drives for user-file scans. GreyWatch's scan session
runs clamscan over the user areas on schedule or on demand.

WHAT ITS WARNINGS MEAN: a detection names the file and the signature
(such as Win.Trojan.*). That is a malware-detected finding with HIGH
severity — the primary action in GreyWatch is **Delete now** (remove the
file + its persistence hooks, record path and hash in the ledger); the
quarantine lane is the undo, not the goal.

HEURISTICS:
- Delete now for anything the scanner flags in /tmp, /var/tmp, Downloads,
  or user homes that the owner does not recognize.
- If the file is needed (owner says keep), Quarantine moves it out of
  reach without executing it — restoring is a conscious undo.
- Stale signatures (update older than a week) are an honesty line on the
  tool card: refresh the DB before trusting a clean run.
- Scan results must never be "suggested next step" text the owner has to
  follow by hand — the button for the step sits on the same row.
