# Changelog

All notable changes to **greywatch** are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
versions with [SemVer](https://semver.org/). The single source for the
current version is `pyproject.toml` (CLI: `python3 cli.py --version`).

## [0.1.0] - 2026-10-26

First public-ready release.

### Added

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

### Changed

- Full decomment/minify pass over the source (comments, docstrings, shell
  and unit files); shebangs intentionally kept for pkexec-executed helpers.

### Security

- PII-free audit before publication: gitleaks (git + dir), trufflehog, and a
  20-pattern battery over the tree and every commit in history — zero
  findings; runtime data, captures, and operator notes are gitignored.