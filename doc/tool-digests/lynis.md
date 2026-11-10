# lynis — system and security auditor

Source: man page lynis(8), digested through the greysearch RAG ingester into gw-tools.

WHAT IT IS: A local auditing tool: `lynis audit system` runs a breadth of
checks (users, ssh, permissions, firewall, services) and scores the box,
emitting warnings and hardening suggestions per test ID. GreyWatch wraps
it as the Deep audit scan mode and as the hardening checklist engine.

WHAT ITS WARNINGS MEAN: findings are hardening gaps, not attacks. Its
suggestions map directly onto GreyWatch's Harden page rows — each row's
button applies the change (through the polkit apply lane) instead of
asking the owner to shell out.

HEURISTICS:
- Deep audit (with lynis) is the periodic truth-teller; run it after
  major changes, not on a loop.
- A hardening row whose primary action is applied keeps its applied
  state; the score bar moves when the change is verified, not merely
  requested.
- Do not auto-apply paranoid-profile rows — strict/paranoid profiles only
  reshape the checklist; the row still asks before it writes.
- Output goes to /var/log/lynis.log; the app reads it as one lane in the
  Activity Log's Findings tab.
