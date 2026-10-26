# Changelog

All notable changes to **greywatch** are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
versions with [SemVer](https://semver.org/). The single source for the
current version is `pyproject.toml` (CLI: `python3 cli.py --version`).

## [0.1.0] - 2026-10-26

First public-ready release.

### Added
- Application icon set from the final side-profile wolf art: sizes 16–256
  plus a light-background variant, and `install-icons.sh` (hicolor app
  icons + freedesktop launcher entry, no root).
- The GTK window sets the default app icon by theme name (`greywatch`).
- Mini status tile (`ui/minitile.py`): a 150px opt-in strip listing the
  daemon's always-on watcher components with restart counts, the appfw
  engine, and all snapshot protections — quiet when healthy, loud when
  not, honest about unreadable/stale snapshots. Off by default; its own
  "start with app" checkbox persists under `mini_tile` in
  `data/greywatch-ui-settings.json`; closing it is a real close.
- `install.sh`: one-command install (substitutes the checkout's path into
  the systemd unit and polkit allowlist, enables + restarts the service,
  installs the user icons/launcher) plus `--check` (verifies a deployment
  against this checkout, including the live unit's effective limits and
  the complete helper allowlist), `--uninstall` (system files only;
  `data/` history is kept), and `--root DIR` staging self-test — the
  same flow `tests/test_install_script.py` runs in the battery.

- Watchdog daemon (`greywatch.service`, root, capped unit) that follows the
  real logs of 17 installed protections via inotify + journalctl and keeps
  one status file and one append-only event record.
- Stdlib-only CLI: `status · events · tail · log · decisions · rules · answer · setup`.
- GTK 4 desktop app (Security, Tools, Harden, Settings, Logs, Wizard, Help)
  with theme round-trip, tray, and pause/resume on real systemd units.
- Guided Harden flow: plain-user baseline probes, review cards, apply-only-
  on-approval through the system's own privilege prompt, backup + journal +
  `Undo last change`.
- App Firewall engine: per-process outbound control in its own nftables
  table with a C queue worker (`appfw/nfq_worker.c`); off by default and
  fail-open by design (a dead engine never locks traffic out).
- CVE refresh timer and watchdog sidecar units.
- Governance and release plumbing: Apache-2.0 LICENSE, SECURITY/CONTRIBUTING/
  CODE_OF_CONDUCT/ACCEPTABLE_USE, CI (tests + gitleaks + CodeQL), pinned-action
  release workflow producing a compiled `.so` bundle with checksums and build
  provenance attestation.

### Fixed
- `install-icons.sh` now creates `~/.local/share/applications` when it is
  missing (on a fresh account the launcher write previously failed and
  aborted the icon install).
- Theme persistence rewrote `data/greywatch-ui-settings.json` wholesale
  (`{"theme": name}`) on every app start, silently erasing every other
  setting in the file — it now merges and preserves unknown keys (this
  is what kept the status tile's `mini_tile` choice from sticking).
- The status tile keeps its 150px size under display-wide theme CSS: the
  tile carries its own small-font styling above the theme cascade, long
  rows wrap, and anything beyond 150px of height scrolls inside the tile
  instead of widening the window.
- README CLI table: `answer` is the decision-recording command (it takes
  an event ID and an option); an earlier wording called it a digest.
- `doc/greywatch.service` template synced to the machine-proven unit:
  50%/768M limits (the original 10%/200M caused a connection-storm
  lockup — remediation documented in the drop-in it came from), the
  NoNewPrivileges/UMask=0077/LockPersonality/RestrictRealtime guards,
  and ExecStopPost removing the appfw nftables table on service stop.

### Changed

- Full decomment/minify pass over the source (comments, docstrings, shell
  and unit files); shebangs intentionally kept for pkexec-executed helpers.

### Security

- PII-free audit before publication: gitleaks (git + dir), trufflehog, and a
  20-pattern battery over the tree and every commit in history — zero
  findings; runtime data, captures, and operator notes are gitignored.