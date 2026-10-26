---
name: Bug report
about: Something behaves differently from what the app or docs claim
labels: bug
---

**What happened** — in plain words, one line at the top.

**What you expected** — what the screen, CLI, docs, or tests led you to believe.

**How to reproduce** — numbered steps from a clean start, including any
scan or setting you pressed.

**Environment**
- Version: `python3 cli.py --version`, or commit if from source
- Distro + desktop (GTK stack matters)
- Which units were running: `systemctl is-active greywatch`
- App-firewall armed? (It is off by default — say which state you were in)

**Output that proves it** — the honest state: paste `cli.py status` output
or a screenshot. Redact anything you consider private first; nothing here
is a private channel. Security issues go to SECURITY.md, not here.