# Security Policy

greywatch is a root-privileged security suite; its own trust model matters
as much as its features. Please use this policy rather than public issues
for anything a misuser or attacker could benefit from before a fix ships.

## How to report a vulnerability

1. **Preferred:** use GitHub's **private vulnerability reporting** on this
   repository (Security tab → "Report a vulnerability"). Nothing is public
   until the maintainer publishes it.
2. **Alternative:** email **[SECURITY-CONTACT-EMAIL]** (replace the
   placeholder in this file with the maintainer address before release).
   Encrypt to the published key if one is published at that address.

Please do NOT open a public issue, attach a crash log to a public
discussion, or paste a traceback that shows paths, hostnames, or the
internal event-store layout.

## What to include

- Component and version/tag (`python3 cli.py --version`), or the commit
  you tested.
- One-paragraph impact guess ("a helper runs with root privileges without
  the polkit prompt because …").
- Minimal steps to reproduce; a failing test is always welcome.
- Environment: distro, Python, GTK stack, and whether the app-firewall
  engine was armed.

## Scope

In scope: everything in this repository — the root daemon and its event
store, the pkexec allowlist and all `apply/` helper scripts, the
app-firewall engine and its nftables table (including the fail-open
bypass guarantee), the GTK app, the CLI, and the build path
(`build-cython.sh`, the compiled `.so` artifacts shipped on tagged
releases).

Out of scope: vulnerabilities in the *driven* tools themselves (ufw,
clamav, fail2ban, Tetragon, …) — please report those upstream; issues in
this repo's packaging *of* them are in scope.

## What happens next

- First response within **7 days** (aim is 48 hours).
- Confirmed issues get a fix on a private branch first, a coordinated
  disclosure note in the release notes, and credit if you want it.
- Nothing about a live report is published without your agreement.

## Design notes for reporters

Three decisions are deliberate, but challenges to them are welcome and
in scope: the app-firewall fails **open** (a dead engine must never lock
traffic out); the event store is root-owned `0600` (owner-only privacy of
security events); and no runtime network fetches are made by the suite's
own code (the machine may be offline — HELP/ carries pre-fetched
reference material instead).