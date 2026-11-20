# yara — YARA (pattern scanner)

Source: man page yara(1) + the GreyWatch yara lanes, digested through the greysearch RAG ingester into gw-tools.

WHAT IT IS: The pattern scanner family. YARA matches rules — textual and
binary patterns stitched into signatures — against files. GreyWatch uses
two lanes: yara-watch (the realtime watcher over watched dirs such as
Downloads) and yara-tmp-scan (the 15-minute sweep of /tmp and scratch
dirs). Rules compile once; a broken ruleset means the lane reports
honestly instead of pretending to scan.

WHAT ITS WARNINGS MEAN: a hit row names the file, the rule that matched
(such as Win.Trojan.Suspect-34) and the acting lane. The match is the
scanners' strongest signal — responderd typically has already
quarantined the file when you read the row.

HEURISTICS:
- A hit on a downloaded file you didn't ask for: keep it quarantined;
  deleting is the responder lane's delete card.
- Rule compile errors are a lane health issue, not a finding: fix the
  ruleset file (the wizard compiles and shows the offending line), the
  watcher resumes on the next cycle.
- Very large archives scanning slowly is expected; the throttle lane
  (nice, idle IO) keeps the scan polite — patience is correct behavior.
- New rules come from trusted feeds only; a rule you wrote yourself
  should be tested against the EICAR test file before you trust the
  negative results it produces.
