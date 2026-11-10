# rkhunter — RootKit Hunter

Source: man page rkhunter(8), digested through the greysearch RAG ingester into gw-tools.

WHAT IT IS: A shell-based checker for known rootkits and malware: modified
commands, changed startup files, suspicious network interfaces and
listening applications. Command family: `--check` (run the tests),
`--update` (refresh detection data), `--propupd` (STORE the current file
properties as the new baseline), `--config-check`, `--unlock`.

WHAT ITS WARNINGS MEAN: a `[ Warning ]` line means a test found a file
whose properties differ from the stored baseline, a hidden file, or a
known-bad string. After LEGITIMATE system changes (package upgrades, your
own config edits), baseline comparisons will warn forever until the
baseline is refreshed: `rkhunter --propupd` stores the CURRENT state as
good. THAT IS THE PERMAFIX — suppression only hides the message.

HEURISTICS:
- Warning right after an upgrade or config edit → verify the change is
  yours → Update baseline (--propupd) from the finding row or the tool
  card, then Re-run to confirm clean.
- Warning on something you did NOT change → treat as a rootkit signal:
  Delete now if it is a malicious file, else inspect before baselining.
  NEVER --propupd to silence an unexplained warning.
- The app runs `--check` on schedule and re-publishes open warnings every
  watcher cycle; resolution keys (rule, subject) so closed ones stay shut.
- Exit codes: 0 clean, 1 warnings, 2 error. The app surfaces code 2 as an
  honest failure, not a finding.
