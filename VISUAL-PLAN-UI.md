# VISUAL-PLAN-UI: restore the 0.1.28-grade layout on the 0.3.0 shell

Written 2026-11-09, read-only plan. Evidence: git tag `v0.1.28` source
(`git show v0.1.28:ui/shell.py`, `:ui/window.py`) against the working tree
(at HEAD `91d339b`, the 0.3.0 redesign line that starts at commit `09c8e2e`
through `deaac97`). Every symbol below was read in real source.

## 1. What went wrong: 0.1.28 vs 0.3.0

The old shell had a four-group, ten-page navigation. It was wide, labelled,
and each page held one subject's real content.

| v0.1.28 (`ui/shell.py` at tag) | v0.3.0 (working tree) | Verdict |
|---|---|---|
| `RAIL` groups Watch / Defense / Care / System, ten labelled pages | one unnamed group of four pages plus a footer pair | grouping and depth deleted; every page must now carry three pages' content |
| `WIDE_RAIL = 152`, glyphs at `win_glyph(key, size=22)` | `WIDE_RAIL = 120`, glyphs at 18 | visibly tinier rail; this is the "so tiny on the left side" half |
| `NARROW_RAIL = 52` glyph-only under `rail_pinned()` (1100 px) | same `rail_pinned`/`collapse_rail` code survives, applied by `window._periodic_refresh` (window.py:854) | still a collapse knob; the default size `WINDOW_MIN_W = 1140` (ui/metrics.py:32) leaves zero margin before the rail loses its labels |
| `Home` page: `SuiteCard`, `HomeDigest`, full-width `AssistantPanel` with `chat_retry`, fixed 110 px recent-activity table (window.py `_home_view`, tag lines 380-517) | `OverviewPage` (ui/console.py:195) packs ribbon + advisories + two-lane feed + right-side 380 px assistant + action gate into one long scroll | the professional Home became a column; the assistant became a right-side pane the owner dislikes |
| separate pages `scans` (`_scans_view`), `protect` (`_protect_view`), `tools` (`_tools_view`), `harden` (`_harden_view`) | `window._LEGACY_PAGE` (window.py:51) folds all four into `"services"` | this map is literally why "everything is on the Services screen" |

Named defects, file and function:

- **Rail shrinks/disappears on Firewall click.** Two code-verified
  contributors. (a) `ui/shell.py rail_pinned()` collapses the rail to the
  52 px glyph column below 1100 px and `window._periodic_refresh` applies
  `collapse_rail` on every 5 s tick, so any relayout nudge or un-maximized
  relaunch flips the labels off. (b) `ui/defense.py DefenseView.refresh`
  (line 231) calls `_paint_armor` (line 615) which runs `psad_status()` and
  `arp_status()` synchronously on the UI thread (line 616-617); each is
  `subprocess.run(..., timeout=5)` from ui/defense.py lines 54-68, so the
  first Firewall click can freeze the main loop for tens of seconds. The
  window paints nothing during that stall, and the 0.3.0 watchdog can
  starve and restart the shell on top (root cause already filed for the
  crash loop).
- **Everything on Services.** `window._LEGACY_PAGE` + the
  `ServicesPage` (ui/toolhealth.py:31) header literally says "Scans" while
  carrying scan actions, `ScanConsole`, `Service Healer` rows and the full
  `ToolsDesk` grid.
- **Weak navigation, weak density.** `ui/shell.py build_rail` renders four
  rows with no group headings; `OverviewPage` stacks five layers on one
  page and `DefenseView.__init__` stacks four more sections
  (Blocked addresses, Decisions waiting, Network armor, Browser Watch) in
  one unlabeled vertical column.
- **No stale snapshot guard.** `window.refresh` (line 879) reads
  `status.json` through `daemon_mod.load_status`; when the file is missing
  or old it returns `{"updated": None, ...}` (status.py:228) and the shell
  still paints a full-looking layout. The only honest state is the
  `known == 0` "Waiting for monitor" pill, which does nothing about a
  stale-but-populated file.

## 2. Target layout

Base shape is the 0.1.28 rail kept, with pages re-spread to hold the
0.3.0 features. Nav rules, hard:

- Fixed `WIDE_RAIL = 176` (wider than 0.1.28: 22 px glyphs, real text,
  badges). `NARROW_RAIL` and `collapse_rail`/`rail_pinned` are deleted; the
  rail NEVER changes width and NEVER hides a row, on click, on resize,
  ever. `window._periodic_refresh` stops calling `collapse_rail`.
- The rail owns its width; no page child may set `hexpand` into the rail
  side of `body` (window.py:112). Keep the no-hexpand rule the shell
  comment already carries.
- Eleven rows under the 0.1.28 four headings; the two-system ordering returns.

```
+------ rail (176px) ------+ +-------- page stack ---------------+
| Watch                    | | Overview: SuiteCard verdict       |
|   Overview               | |   recent-activity table, pinned   |
| Defense                  | |   notes; chat below the feed      |
|   Firewall               | |   armor chips / Browser Watch     |
|   Threat Hunter          | | Threat Hunter: hunter feed        |
| Care                     | | Scans: modes, ScanConsole         |
|   Scans                  | | Protections: dossier on-select    |
|   Protections            | | Tools: registry grid + dossier    |
|   Tools                  | | Harden: checklist rows            |
|   Harden                 | | Watchlist: ptp coverage cards     |
|   Watchlist              | | Activity Log: 3 tabs + filter     |
| System                   | | Settings: settingsdesk panes      |
|   Activity Log           | +-----------------------------------+
|   Settings               |
|   Help                   |
+--------------------------+
```

Screen by screen (where each 0.3.0 feature lands):

- **Overview.** The 0.1.28 `_home_view` shape again: `SuiteCard` verdict
  first, `HomeDigest` pinned notes next, the fixed-height recent-activity
  table, and the assistant BELOW the feed as a centered panel with the
  `chat_retry` button, not a right-side 380 px column. `OverviewPage`'s
  `_StatCard` ribbon shrinks to four tiles (tools online, pending
  decisions, blocked, watchlist HIGH) and moves onto SuiteCard's row; the
  two-lane feed, `MetadataCard` and action-gate rows move to Firewall /
  Activity Log; `OverviewPage` stops being a scroll pit.
- **Firewall** (ui/defense.py `DefenseView`, keep the class). Same four
  sections but a two-column grid: blocked-address table and
  decisions-waiting rows left, armor chips and `cve_rows` findings right,
  Browser Watch cards across the bottom. Mandatory: `psad_status`/
  `arp_status` probes move off the UI thread (background thread or a
  cached daemon-published digest); the page paints instantly.
- **Threat Hunter.** `hunterview`/hunter feed returns as its own page
  (the badge count `home_unread` moves from the Firewall badge back to
  the hunter badge).
- **Scans.** The `_SCAN_ACTIONS` action strip and `ScanConsole` only.
- **Protections.** The protect desk (`protectdesk.py`) with scan history
  cards; `_run_protection` keeps routing here. No tools grid.
- **Tools.** `ToolsDesk` registry grid, dossier, `show_all_btn` filter.
- **Harden.** The harden checklist page (`ui/harden.py`, `_harden_view`).
- **Watchlist.** The ptp `ptp_rows`/`ptp_high_count` content: coverage
  cards, watch stamp, `ptp_probe_failed` honesty, "Ask the assistant"
  hand-off, and the browser-watch findings from `DefenseView._paint_watch`
  (the daemon can keep publishing both keys; the page reads them via
  `browser_watch`). `_LEGACY_PAGE` maps `"watch": "services"`-style fallout
  to it.
- **Activity Log.** Unchanged 0.3.0 three-tab page (it is good), plus the
  tool-lane metadata card.
- **Settings, Help.** Unchanged (`settingsdesk.py`, `helpdesk.py`).
- **Header.** Unchanged 0.3.0 header (title, Setup button, decision pill).
  New: a stale-snapshot state, see below.

Stale snapshot guard (every page, one gate): in `window.refresh`, compute
age from `snap.get("updated")`; older than 90 s (or `None`) sets a
`_stale` flag. While `_stale`, the page stack shows a single centered
"waiting for the daemon" panel (last snapshot summary hidden, controls
left built but grey) exactly like the `known == 0` "No status yet"
branch, and the header pill switches to "Waiting for the daemon" with
`warn` styling. The guard must come back the instant a fresh snapshot
arrives, and the 5 s tick keeps checking.

## 3. Implementation route, Cython twins, test gates

Files and functions, in change order:

1. `ui/shell.py`: re-grow `RAIL` (4 groups, 11 rows), raise
   `WIDE_RAIL = 176`, delete `NARROW_RAIL`/`collapse_rail`/`rail_pinned`;
   `rail_size` returns the constant.
2. `ui/window.py`: `_periodic_refresh` drops the collapse calls;
   `_LEGACY_PAGE` maps to the restored keys (`tools` -> `tools`, etc.);
   `_builders` re-adds `home`/`assistant` decision, `thunter`, `scans`,
   `protect`, `watchlist`; `refresh` grows the stale guard; badges split
   (`defense` blocked count, `thunter` unread, watchlist HIGH count).
3. `ui/console.py`: `OverviewPage` rebuilds to the Home shape; extract
   the gate rows helper used by any page.
4. `ui/toolhealth.py`: `ServicesPage` loses the tool grid and healer
   (they return to their own pages).
5. `ui/defense.py`: `DefenseView.refresh`/`_paint_armor` go threaded; the
   page composes on the grid. `ui/toolhealth.py` and `ui/homepage.py`
   twins touch `ptp_rows`.
6. `ui/settingsdesk.py`: re-add the `related_box` footers to the new keys.

Cython rebuild order (repo ships Cython-twinned modules; `build-cython.sh`
compiles every non-entrypoint .py, preferring .so on import):
1. plain `git status` first; 2. edit the .py twins above;
3. `python3 -m pytest tests/test_tab_shell.py` (fast source-lane check
   against .py); 4. after all edits: `./build-cython.sh` once at the end,
   it rebuilds all twins in one pass (`ui/shell.py`,
   `ui/window.py`, `ui/console.py`, `ui/toolhealth.py`, `ui/defense.py`,
   `ui/settingsdesk.py` land as .so next to the .py); 5. reinstall or
   drop the new `ui/shell.cpython-313-*.so` plus siblings into
   `/opt/greywatch/ui/` beside the 5,011-byte `app.py` stub.

Test gates that exist (all live under `tests/`):
`test_tab_shell.py` (rail rendering, `test_rail_renders_four_pages_and_a_footer`
will need its name updated), `test_rail_scrollbar.py`,
`test_ui_smoke.py`, `test_gw207_defense_rebuild.py`,
`test_gw208_console_services.py`, `test_gw205.py` (imports
`ui.shell`), `test_harden_shell.py`, `test_hunter_page.py`,
`test_hunter_ui.py`, `test_ui_visuals.py`, `test_ui_polish.py`,
`test_assistant_window.py`, `test_settings_depth.py`,
`test_bug_sweep_sizing.py`, `test_ui_metrics.py`. Run:
`python3 -m pytest tests/ -x -q -k "not slow"`.

## 4. Phased ship order (each phase independently verifiable)

- **Phase 1: nav is real again.** shell.py RAIL regrows to 4 groups/11
  rows at 176 px, collapse code and its periodic call deleted.
  Verify: `test_tab_shell.py` green, screenshots show a labelled rail
  after clicking Firewall.
- **Phase 2: stale guard.** window.refresh 90 s gate + "waiting for the
  daemon" panel + pill word. Verify: with `status.json` mtime aged past
  90 s the pages show the panel (unit test pins it).
- **Phase 3: Firewall stops freezing.** defense probes threaded, page
  paints instantly on show. Verify: `test_gw207_defense_rebuild.py` plus
  a timing assertion that `_show("defense")` runs no subprocess.
- **Phase 4: Services unloads.** Protections, Tools, Scans, Harden are
  pages again; `_LEGACY_PAGE` updated. Verify:
  `test_gw208_console_services.py` re-rooted, one subject per page.
- **Phase 5: Overview rebuild.** Home shape returns, assistant pane moves
  below the feed, ribbon folds into SuiteCard. Verify:
  `test_assistant_window.py`, `test_ui_smoke.py`.
- **Phase 6: Watchlist page.** ptp cards move off Firewall and Overview
  to their own row. Badge moves with it.
- **Phase 7: Cython twins + install.** `./build-cython.sh`, drop the new
  .so set into `/opt/greywatch/ui/`, launch, and eyeball the full rail
  and every page against this spec before telling the owner.

Phase 1 and 2 alone already answer both owner sentences: the left side
stays, and the app admits when the daemon is quiet.

## 5. Page-subject audit (owner directive 2026-11-09: "clearly define each
page so they work together and don't show the wrong tools on the wrong
pages")

The governing rule: **one subject per page; a page may point at another
page with a button, never re-display that page's content.** Verdicts
below are read from the repo at HEAD (`hunter/engine.py`,
`ui/hunterview.py`, `ui/defense.py`, `ui/toolhealth.py`,
`decisions_factory.py`).

| Page | Its one subject | On it today that is wrong | Where it goes |
|---|---|---|---|
| Overview | "Am I OK right now": SuiteCard verdict, 4 stat tiles, recent-activity table | two-lane feed; watchlist cards; action-gate rows | feed -> Firewall / Activity Log; watchlist -> Watchlist |
| Firewall (renamed from Defense) | network access control: blocked addresses, decisions waiting, allow/block state | the "Network armor" CVE wall — up to 24 raw CVE rows read straight out of `cve-cache.json` (`defense.py:626 cve_rows`) — this log wall is why the owner read the page as "just logs" | CVE rows -> Protections advisories |
| Threat Hunter | what the daemon's always-on watcher caught while you worked | `rootkit-warning` and `scan-positive` findings — these are one-shot scanner outputs re-published by `hunter/engine.py:196,225` | scanner findings -> Scans page (their producing tool), see below |
| Scans | run the suite, watch runs, read run output | (currently folded into Services) | becomes its own page again with rootkit/scan findings routed here |
| Protections | what stands between this box and threats: scanner run cards + patch advisories | (currently folded into Services) | gets the CVE advisory list with severity + affected tool per row |
| Watchlist | Patch-the-Planet coverage + browser-watch findings | cards living on Firewall/Overview | own page (Phase 6) |
| Activity Log | the only place raw rows exist | — | stays the three-tab page |

Naming: the label "Sidekick questions" (installed 0.1.28 build) is dead
language — the sidekick was retired; the repo already renamed it
"Decisions waiting". Defense -> Firewall rename lands with Phase 1.

### Hunter findings stop being copy-only (enforcement rule)

Every finding detail carries its rule's one real action, wired to
machinery that already exists, via a rule→action map in
`ui/hunterview.py` next to `_RULE_CHANNELS`:

- `malware-detected` -> **Quarantine now** (the responderd quarantine
  decision lane in `decisions_factory.py` already keeps/deletes
  quarantined files); plus "Run a full scan" -> Scans page.
- `rootkit-warning`, `scan-positive` -> **Follow up in Scans**
  (navigate + select the producing tool in `_SCAN_ACTIONS`, prefill the
  console); re-run button on the same row.
- all findings keep Ask about this / Dismiss / Copy facts.
- The finding's "SUGGESTED NEXT STEP" text stops being a sentence the
  user must execute by hand — where the step names a thing above, the
  button for it is on the same row.

Ship this as part of Phase 4 (page split) in `ui/hunterview.py` /
`ui/toolhealth.py`; test gate: extend `test_hunter_page.py` with an
"every rule kind has its action wired" assertion.

## 6. The warning never closes (user-journey evidence, 2026-11-09)

The owner's report "not allowing us to USE the tools, just giving us
warnings" traced to code, end to end:

1. **The source.** `greywatch-boot-sweep.service` (ExecStartPre sleep 180)
   runs `rkhunter --check --report-warnings-only`, `lynis audit system`,
   aide and the user clam scans **3 minutes after every boot** — that is
   the only recurring schedule; `scan_session.py` has no daily timer.
2. **The republish loop.** The resident hunter
   (`greywatch-hunter.service`, `hunter/main.py INTERVAL_S = 300`) reads
   new lines of `/var/log/rkhunter.log` each cycle and re-publishes any
   `Warning`/`Susp` line as a `rootkit-warning` finding
   (`hunter/engine.py:194`). Suppression is per-rule by hours
   (`SUPPRESS_HOURS`, engine.py:33): rootkit-warning 72 h,
   scan-positive 720 h, malware-detected 0.
3. **Why Dismiss never works.** Each re-fire is a NEW finding id;
   dismissal (`hunter/store.py quieted_ids`) keys on id — so the same
   underlying warning returns every 72 h forever. The Nov 6,6,6,7,7 rows
   in the screenshots are this loop, not repeated detections. Closing it
   permanently needs the real fix: refreshing rkhunter's baseline with
   `rkhunter --propupd` after the change is verified — **no code path in
   the repo touches --propupd** (only AIDE baselines exist under
   `scan_session.py`/`setup.py`).
4. **RAM: the UI process, not the daemon.** Live 2026-11-09: daemon RSS
   48 MB, hunter 38 MB, but `python3 /opt/greywatch/ui/app.py` sits at
   **2.6 GB** — `smaps` shows 1.04 GB mapped
   `/var/lib/greywatch/models/Qwen3-1.7B-Q4_K_M.gguf` plus ~1.2 GB
   anonymous llama.cpp working memory. `ui/app.py:171` wakes this model
   **automatically on every window open** and no unload path exists
   (`assistant/llm.py` has no release). Fix plane: load only on first
   ask/explain, unload on idle, or retire the in-window gguf in favor of
   the box's cloud intern lane (:11600 directive).
5. **CPU at start.** The boot sweep is the swamp: six scanners plus
   daemons all arm within a 3-minute window after every boot
   (`nice 19 ionice -c3` for rkhunter/lynis is the only throttling;
   systemd caps also exist in `scan_session.py THROTTLE`). Fix plane:
   stagger scanners one-per-slot (daemon re-arm loop already has slot
   machinery) and surface the schedule on the Scans page instead of
   hiding it in a systemd timer.

## 7. Design law: resolve everything (owner directive 2026-11-09)

Owner, verbatim: "I MUST BE ABLE TO CLEANLY AND QUICKLY RESOLVE ANY ISSUE.
ANYTHING BROUGHT TO THE USER'S ATTENTION MUST BE ABLE TO BE ENFORCED OR
UNBLOCKED AND ALLOWED IMMEDIATELY. IT MUST BE CLEAN AND EASY TO SEE. NO
REDUNDANCY. EVERYTHING CLEARLY LABELED." This is the acceptance gate for
every page in §2 and every fix in §5/§6 — a row that cannot be closed from
its own row fails review.

The four laws, applied concretely:

1. **One-click resolution, wired, immediate — and permanent by default.**
   Each item type carries its real action(s) on the same row, and the
   primary button changes durable state (owner addendum same day: "malware
   should be allowed to be deleted cleanly and safely and not just
   quarantined. other things should be permafixed and not just locked or
   temp patched"):
   firewall popup (unknown program) → Allow / Block this program **saved
   as a permanent rule**, no timer pressure (#9 lane); hunter
   `malware-detected` → **Delete now** (primary: remove persistence
   hooks, record path + hash in the ledger, never execute) with
   Quarantine demoted to a secondary undo lane, plus Run full scan;
   rootkit/scan warnings → Update baseline (`rkhunter --propupd`, aide
   `--update`) + Re-run in Scans; blocked address → Unblock; decision row
   → Keep / Delete / Restore (responderd lane). Suppress-only or
   timer-style measures are stopgaps, never a row's primary button. "Copy
   text" is never a resolution.
2. **Resolved stays resolved.** "Ignore forever" and baselines key the
   phenomenon (rule + subject), not the instance id, so a closed item
   does not return on the next 72 h refire (§6.3).
3. **No redundancy.** An issue exists in exactly one page; other pages
   point at it with a navigation button, never re-display it (§5 table
   is the map, `_LEGACY_PAGE` folds must not resurrect copies).
4. **Clearly labeled.** Pages named for their subject (Defense →
   Firewall), actions named for the effect (Allow / Block / Quarantine
   now / Update baseline / Ignore forever), and after the action the row
   states plainly what happened ("Allowed chrome — added to firewall
   rules") or hands back an honest failure.

### Resolution states to build (task #10)

Every hunter finding row gains **Fix** (malware: **Delete now**, safe
deletion via the responderd quarantine lane, quarantine as undo; scanner
warnings: re-run the owning tool through `_SCAN_ACTIONS`), **Update
baseline** (rkhunter `--propupd`, aide `--update`, after the finding
explains what changed), **Ignore forever** (quieted_ids keyed on
rule+subject, not id), and **Escalate** (write a decision row). Primary
buttons are the permanent fixes; quarantine and suppression exist only as
secondaries.
