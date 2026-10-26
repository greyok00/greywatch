---
name: Feature request
about: A capability that would make the dashboard more honest or useful
labels: feature
---

**The gap** — what can't you see or do with greywatch today? One paragraph.

**What you would press or run** — the screen element, CLI verb, or config
shape you imagine. If it needs a new privileged helper, say so plainly:
helpers live in `apply/`, are pkexec-allowlisted, validate argv, and back
up before touching anything (CONTRIBUTING.md explains the rails).

**Why it belongs in this project** — defensive, single-machine, works
offline, fails honest (CANT-CHECK, never a silent pass). Features that
network-fetch at runtime or centralize control don't fit the design;
"acceptable use" in ACCEPTABLE_USE.md is the boundary.

**Willing to build it?** A failing test + a draft makes adoption fast.