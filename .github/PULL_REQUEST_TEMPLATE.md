## What and why

One paragraph a reviewer can hold. If this touches **privilege** (`apply/`,
polkit, pkexec) or the **event store**, say it in the first line.

## Blast radius

Which units, tools, or data files can this change affect on a running
machine? Name them.

## The three repo rails (check what applies)

- [ ] Privilege stays a list: helpers remain pkexec-allowlisted, argv-validated,
      backup-before-write
- [ ] App firewall still fails open (a dead engine cannot lock traffic out)
- [ ] No new runtime network fetches (offline discipline; see HELP/)

## Proof

- [ ] `ruff check .` passes
- [ ] `python3 -m pytest tests/ -q` passes headless; new behavior has a test
- [ ] User-facing strings stay under the copy-length rules (tests assert them)

## Notes

Anything that cannot be tested locally (a real unit, a real pkexec prompt,
a real display) gets spelled out here rather than claimed. Screenshots:
real desktop captures stay out of the repo (PII discipline of this project).