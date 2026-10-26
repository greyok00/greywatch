# Acceptable Use

greywatch is a **defensive** endpoint tool for a machine you own or are
authorized to administer. It lines up the security tools already on a
Linux box, reports what they are doing in plain words, and makes
privileged changes only when a human presses the button — recording and
reverting each one.

## You agree that you will only use greywatch on systems you are
## authorized to touch

- Run discovery, monitoring, blocking, and hardening **only on machines
  and networks you own or have explicit written permission to assess**.
  The wizard's LAN discovery exists to inventory *your own* network, not
  to profile anyone else's.
- Do **not** use greywatch to monitor, decide about, or restrict other
  people without their knowledge and any consent the law requires
  (workplace and household monitoring have legal limits in most
  jurisdictions — they are yours to know).
- Do **not** remove, override, or weaponize the safety rails the project
  respects: the pkexec allowlist (only listed helper paths can be
  privileged, each pinned to exactly one helper), argv validation, the
  backup-before-change journal, and the fail-open app-firewall design.
- Do **not** use this project as part of unauthorized access, malware
  operation, harassment, or evidence fabrication. Security research with
  authorization is fine; the project's own tests and fixtures show what
  that looks like.

## Privilege and blast radius

The daemon runs as root by design: reading root-only security logs is the
whole point. Privileged *changes* go through your system's own polkit
prompt against an allowlist of helper scripts that validate arguments,
back up what they touch, and roll back on undo. Treat any report of a
bypass for these rails as a security report (see SECURITY.md).

## No warranty

greywatch is provided under its LICENSE, WITHOUT WARRANTY OF ANY KIND,
express or implied, including merchantability and fitness for a
particular purpose. You are responsible for backups (the suite journals
its own changes, but it is not a backup system) and for the legal
use of the security tools it drives on your machine.