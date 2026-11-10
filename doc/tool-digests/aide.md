# aide — Advanced Intrusion Detection Environment

Source: man page aide(1), digested through the greysearch RAG ingester into gw-tools.

WHAT IT IS: A file-integrity checker. It builds a database of checksums
and attributes over chosen paths (aide.conf), compares the current system
against it, and reports NEW / CHANGED / REMOVED files. Commands:
`aide --init` (first DB), `aide --update` (refresh baseline AND compare),
`aide --check` (compare only), `aide.conf` holds the rule set.

WHAT ITS WARNINGS MEAN: differences are integrity observations. Most noise
comes from normal package activity — the fix is the same as rkhunter:
verify the change is expected, then refresh the baseline (`--update`).

HEURISTICS:
- After an update/upgrade cycle, run Review diff → if every difference is
  a package file, Update baseline; do not stack weekly drift.
- Changed files OUTSIDE package managers (in /etc, /usr/local, home
  dotfiles you did not touch) are intrusion signals: Delete now for
  malware, inspect otherwise, never baseline over them.
- A missing baseline is an "honest failure" state: initialize it first,
  the app offers that from the tool card.
- Resolution keys (rule, subject): one resolved drift stays resolved even
  if the watcher re-reads the same log lines.
