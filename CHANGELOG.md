# Changelog

Every line of GreyWatch, newest first. Dates are the day the line was
finished (public posts happened only where a release line says so).

## 0.3.0 - 2026-11-07 (local tag; push waits for the owner's grants)

- Phase 4 of the rebuild is closed for good: the tool lifecycle block
  (pause and resume dialogs, panic lockdown, manual scan triggers, the
  per-tool detail card) moved out of `ui/window.py` into the
  `ui/toolctl.py` mixin, and the shell sits under the target size again.
  The mixin reaches its data through the window's own `self.data_dir`,
  so test isolation and GREYWATCH_DATA_DIR keep working unchanged.
- Test re-root: the scan-escalation pin reads `ui/toolctl.py` sources
  where the moved code lives (replace-pin, not delete).
- The 1.0 gap audit: `docs/1.0-gap-audit.md` separates the owner-supplied
  gaps (push grants, the daemon service restart, final approval) from
  the code gaps this line closes.
- This changelog itself, plus the man page for the CLI, plus the README
  fact refresh, close the documentation half of the 1.0 gap.
- Test-harness livelock fix: the chooser test silences its window's
  5s periodic and 1s scan timers (the tab_shell "silence the periodic
  tick" precedent) and every GTK pump checks its clock per dispatch,
  so a full data-dir refresh running on a timer can no longer pin the
  suite to minutes of hidden refresh work.

## 0.2.0 - 2026-11-07 (local tag; pushes wait for the owner's grants)

- The rebuild line folds the never-shipped 0.1.29 rail fix (commits
  from 9fc194c through 01165c8).
- Front-end rebuild: four pages (Overview, Firewall, Services, Activity
  Log) in a sidebar rail with a Settings/Help footer, one decision list
  counted in one place, plain-functional names (Assistant, Block
  Reviewer, Browser Watch, Service Healer; "sidekick" purged), the
  obsidian/slate dark voice rebuilt on literal-CSS tokens.
- Watchlist line: the Patch the Planet map ships as a snapshot,
  refreshes daily, matches coverage against this machine's own package
  channels, and cross-joins the CVE lane; Defense explains patch
  intents through the assistant.
- Unconfuse wave: every log row resolvable, every surface links its
  owner page.
- Cannot-fail sweep: announcement ledgers retry until persisted, failed
  reads always name themselves, the doctor gains four honest lanes with
  a machine mode (`doctor.py --machine` prints `DOCTOR <n_red>
  <n_yellow>`), and per-cycle health publishes through status.json.
- Human-style visual audit: 58 screenshots across 5 driver runs became
  the walkthrough manual (`docs/manual/walkthrough.md` and its PDF)
  plus three UI fixes (detail card scroll, time column width, watch
  row text).
- Packaging: deb, wheel, and tarball recut with checksums after every
  wave; ABI facts stay pinned exactly as the 0.1.7 lesson wrote them
  (deb Depends derived from the compiled ABI; ubuntu-24.04 pins the
  bundle ABI).

## 0.1.28 - 2026-11-06 (released)

- The wave-D line: sidebar rail (Watch, Defense, Care, System), the
  Defense page with block rows and answerable question cards, armor
  probe chips that report Active, Exposed, or Cannot Read (never
  "safe" on unreadable), two-lane tokens and four new glyphs.

## 0.1.27 - 2026-11-06 (released)

- psad as a managed tool: parsers, auto-block at the danger threshold
  only, LAN and gateway whitelisted, the kern.log bridge fixed (the
  deafness root cause - psad read a file modern installs never write).
- ARP hardening helper: gateway pin plus arp sysctls.
- The block ledger: append-only blocked-ips.jsonl, the block reviewer's
  hash-free classification (own infra, CDN, datacenter), re-arming of
  keeper blocks, lift and review helpers, question-never-fix enforced.
- The CVE lane: scored active rules only (7.0 and up), announced fail
  closed, one-hour daemon watch, no auto-patching (test-pinned).

## 0.1.26 - 2026-11-06 (released)

- The two-lane law: `events.lane_for()` splits threats from tools at
  read time; every control a surface offers matches its lane (a threat
  row never grows a Start tool button; a tool row never grows a
  quarantine button). Two faces on the critical square, click-to-fix
  cards on log rows.
- Quarantine discipline: purge through delete/restore helpers with an
  explicit exit-code contract.

## 0.1.25 and earlier (2026-11-05 and before)

- Program build-out: registry probes, supervisor and healer, hunter
  lane, parsers and enrichment, the first doctor, the wizard, tray,
  and the packaged release line from v0.1.6 through v0.1.25.
