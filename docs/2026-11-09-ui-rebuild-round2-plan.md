# GreyWatch UI rebuild round 2 — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebuild the GreyWatch UI on the 0.3 shell per `docs/2026-11-09-ui-rebuild-round2-design.md`: graphite/paper theme voices, thin always-visible rail with the owner's 10-page menu, three-pane frame with per-page control docks, guided-attention pulses/pointers with hand-off auto-navigation, per-page layouts as picked, full tool control with in-card raw-config editing and the baseline permafix loop, two-tier assistant (heuristics always; owner-toggled resident GPU model), and the fix-wave behavior carried over with recreated pins.

**Architecture:** The repo's existing modules stay (window.py shell entry, page modules, daemon publishes status.json). Changes: theme token system gets the two owner voices; rail/`_LEGACY_PAGE` regrow to the 10-page menu; window gains a DockHost (one dock per page) and a GuidedLayer (pulse + pointer + hand-off router); page modules rebuild their layouts; toolsdesk gains the config-edit lane; assistant gains the tier gate. The repo ships open readable Python (owner law 2026-11-10): no Cython, no .so, anywhere.

**Tech Stack:** Python 3.13, GTK4 (gi), pytest, Cython (repo twins), no new pip dependencies, no new model, no ollama/network in GreyWatch.

## Global Constraints

- Spec: `docs/2026-11-09-ui-rebuild-round2-design.md` (owner-verified through visual-planner round 2). Where this plan compresses, the spec wins.
- HARD: no ollama, no cloud, no external server anywhere in GreyWatch; assistant = local gguf (GPU offload) + heuristics; model loads ONLY on the owner's toggle, stays resident until toggled off, NEVER on window open/actions/timers.
- HARD: rail never collapses/hides/truncates; every row resolves on its own row (primary button = the permanent fix); one subject per page; resolved stays resolved (key rule+subject, never the instance id alone).
- Global Constraints: no new pip dependency, no new model (gameplan C5). NO CYTHON (owner law 2026-11-10): the tree ships plain .py only; `build-cython.sh` and every .so are removed; tests import .py sources; entry points (ui/app.py, ui/tray_helper.py) stay plain.
- Tests run: `python3 -m pytest tests -q` from the repo root; every task ends green before commit. UI tests stay headless (GTK objects built but not main-looped, per existing test patterns in tests/test_tab_shell.py).
- Palette: validate categorical sets at build time against BOTH surfaces with the dataviz skill's `scripts/validate_palette.js` (re-invoke the dataviz skill to get its base dir if the path is stale). Dark surface `#14161a`, light surface `#f4f4f2`.
- Language: pages/actions named for their subject/effect ("Firewall", "Delete now", "Update baseline"); no "Sidekick"/retired naming; no em dashes in UI copy.

---

### Task 1: Theme voices — graphite default + paper light

**Files:**
- Modify: `ui/themes.css` (replace both `[data-theme]` sheets)
- Modify: `ui/themes.py` (default voice, migrate pick, sun/moon persistence)
- Test: `tests/test_theme_voices.py` (new)

**Interfaces:**
- Produces: `THEMES = ("graphite", "paper")`; `DEFAULT_THEME = "graphite"`; `themes.py:load_themes()` unchanged signature (parses the new `[data-theme="graphite"...]` / `[data-theme="paper"...]` sheets); `persist(name)`/`active_theme()` unchanged signatures; `CURRENT` token dict keys unchanged (`accent`, `ok`, `warn`, `fail`, `bg`, `panel`, `ink`, ...) so all consumers keep working.
- Consumes: nothing from earlier tasks.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_theme_voices.py
import ui.themes as themes

def test_graphite_is_default():
    assert themes.DEFAULT_THEME == "graphite"
    assert "paper" in themes.THEMES and "graphite" in themes.THEMES

def test_sheets_parse_and_carry_tokens():
    names = themes.load_themes().keys()
    assert {"graphite", "paper"} <= set(names)
    for name in names:
        css = themes.themes_css_text()  # helper the test reads the sheet through
        assert "--el-accent" in css and "--el-ok" in css

def test_migrated_pick_graphite_default(monkeypatch, tmp_path):
    persist_path = tmp_path / "theme"
    monkeypatch.setattr(themes, "THEMES_CSS", tmp_path / "themes.css")
    # a saved pick of a RETIRED voice (agency/aperture) resolves to graphite
    import json
    (tmp_path / "state.json").write_text('{"theme": "aperture"}')
    assert themes.active_theme(path=tmp_path / "state.json") == "graphite"
```

- [ ] **Step 2: Run test to verify it fails** — `python3 -m pytest tests/test_theme_voices.py -q` → FAIL (`DEFAULT_THEME` is `aperture`, sheets are agency/aperture).

- [ ] **Step 3: Implement.** Rewrite `ui/themes.css` as two sheets:
  - `graphite`: `--el-bg: #14161a; --el-panel: #1c1f25; --el-panel-2: #21252c; --el-panel-3: #2e323b; --el-line: #2e323b; --el-line-2: #3a3f49; --el-line-strong: #4a5160; --el-ink: #e9e7e2; --el-ink-soft: #b5b3ab; --el-mute: #8b8a84; --el-on-accent: #14161a; --el-accent: #b5b3ab; --el-accent-hover: #d6d4cd; --el-accent-soft: rgba(181,179,171,.14); --el-ok: #5fae7e; --el-warn: #d9a34a; --el-fail: #d05f5f; --el-info: #b5b3ab; --el-teal: #6aa39c; --el-lane-threat: #d05f5f; --el-lane-tool: #6aa39c;`
  - `paper`: keep the current agency values verbatim (bg `#f4f4f2`, ink `#171715`, ok `#41684b`, warn `#8a5d14`, fail `#a83a2a`, ink-as-accent).
  - In `ui/themes.py`: `DEFAULT_THEME = "graphite"`, `THEMES = ("graphite", "paper")`, THEME_CHOICES = {"Dark": "graphite", "Light": "paper"}; migrate-able retired names (`agency`→paper, `aperture`→graphite) inside the existing saved-pick read path.
- [ ] **Step 4: Run suite** — `python3 -m pytest tests/test_theme_voices.py tests/test_ui_themes.py tests/test_theme_radio.py -q` → green (re-root those two existing tests to the new names if they pin old ones).
- [ ] **Step 5: Commit** — `git commit -am "theme: graphite default + paper light, retired voices"`

### Task 2: Rail — owner 10-page menu, ~5% width, fixed, sun/moon

**Files:**
- Modify: `ui/shell.py` (`RAIL`, `WIDE_RAIL`, delete `NARROW_RAIL`/`collapse_rail`/`rail_pinned`)
- Modify: `ui/window.py` (`_periodic_refresh` drops collapse calls; rail footer toggle)
- Test: `tests/test_tab_shell.py` (re-root), `tests/test_rail_scrollbar.py`

**Interfaces:**
- Produces: `shell.HEADINGS = ("Overview", "Care", "Defense", "System")` and `shell.RAIL = (("scans", "protect", "tools", "harden"), ("defense", "thunter"), ("logs", "settings", "help"))` — group i of RAIL renders under HEADINGS[i]; Overview is HEADINGS[0] itself and IS the home row (clickable large title, no separate Home row). `shell.rail_size(win_width)` = `max(150, min(200, round(win_width * 0.05)))`; `shell.set_theme_toggle(win)` adds the sun/moon Gtk.Button pinned to the rail footer (bottom-left), signaling `window._toggle_voice()`.
- Consumes: Task 1's voices.

- [ ] **Step 1: failing test** (in tests/test_tab_shell.py):

```python
def test_rail_groups_and_order():
    rows = [k for g, keys in shell.RAIL for k in keys]
    assert rows == ["scans", "protect", "tools", "harden", "defense", "thunter", "logs", "settings", "help"]
    assert shell.HEADINGS == ("Overview", "Care", "Defense", "System")

def test_rail_never_collapses():
    assert not hasattr(shell, "NARROW_RAIL") and not hasattr(shell, "collapse_rail")

def test_rail_width_is_five_percent():
    assert shell.rail_size(1200) == 150        # floor holds labels
    assert shell.rail_size(2400) == 120        # 5% with floor -> 120? NO:
    # pin: rail_size = max(150, min(200, round(w*0.05)))
    assert shell.rail_size(3600) == 180
    assert shell.rail_size(9999) == 200
```

(Correct the arithmetic once: `max(150, min(200, round(w*0.05)))` — 1200→150, 2400→120→150 floor, 3600→180, 9999→200. The test pins floor+ceiling, NOT raw 5% below the floor.)

- [ ] **Step 2: verify FAIL** (old RAIL shape, NARROW_RAIL exists).
- [ ] **Step 3: implement** shell.py/window.py per the interfaces above; sun/moon button calls `window._toggle_voice()` which flips the voice via `themes.set_active_theme()`, persists, and re-applies CSS.
- [ ] **Step 4: green** — `pytest tests/test_tab_shell.py tests/test_rail_scrollbar.py tests/test_ui_smoke.py -q`.
- [ ] **Step 5: commit** — `rail: owner 10-page menu at 5% fixed width, sun/moon footer`.

### Task 3: Three-pane frame + DockHost

**Files:**
- Create: `ui/dock.py` (DockHost: `DockHost(win)` with `.set_page(key, groups)`, `.flash(title_group)`; groups = list of `("Title", [widgets])`)
- Modify: `ui/window.py` — body splits rail | feed | dock; `_builders` gain per-page dock specs `PAGE_DOCKS: dict[str, callable(win) -> groups]`; dock width = `max(220, min(320, round(content_w*0.26)))`, Settings-tunable.
- Test: `tests/test_dock_host.py` (new)

- [ ] **Step 1: failing test**

```python
def test_dock_host_sets_groups():
    host = dock.DockHost(win)
    host.set_page("logs", [("Filter", [Gtk.Entry()]), ("Sources", [Gtk.CheckButton(label="psad")])])
    assert host.current == "logs"
    assert host.group_titles() == ["Filter", "Sources"]

def test_dock_width_bounds():
    assert window.dock_width(2400) == max(220, min(320, round(2400*0.26)))
```

- [ ] **Step 2: FAIL, Step 3: implement dock.py + window wiring,** every page builder returns `(content, dock_groups)` — pages without controls pass `[]` (Activity Log's tabs row stays in the FEED; the dock holds filter/sources/actions so controls never scroll away). Same task: `window.refresh` gains the STALE-SNAPSHOT GUARD — age from `snap.get("updated")`; older than 90 s (or None) sets `_stale`: while stale, the page stack shows the single centered "waiting for the daemon" panel and the header pill reads "Waiting for the daemon" (warn styling); returns the instant a fresh snapshot lands; the 5 s tick keeps checking. Pin: `tests/test_dock_host.py::test_stale_guard_shows_waiting_panel`.
- [ ] **Step 4: green**, **Step 5: commit** `frame: three-pane with per-page DockHost`.

### Task 4: GuidedLayer — pulse, pointer, hand-off router

**Files:**
- Create: `ui/guided.py` (`pulse(widget)`, `point(widget)`, `handoff(win, page_key, dock_group, row=None)`)
- Modify: `ui/window.py` (`_show(key)` fires guided.entry(page)); Overview "Needs you" items call `handoff`; new Settings toggle `auto_jump` (default True, persisted)
- Test: `tests/test_guided.py` (new)

- [ ] **Step 1: failing test**

```python
def test_entry_pulses_dock_title():
    calls = []
    guided.pulse = lambda w, c=calls: calls.append(w)   # instrument
    win._show("logs")
    assert calls, "page open must pulse its entry target"

def test_handoff_routes_once(monkeypatch):
    win._toggles["auto_jump"] = True
    sent = []
    monkeypatch.setattr(guided, "navigate", lambda w, key: sent.append(key))
    guided.handoff(win, "defense", dock_group="Rules", row=None)  # once only:
    guided.handoff(win, "defense", dock_group="Rules", row=None)  # same item seen again
    assert sent == ["defense"]
```

- [ ] **Step 2–5:** TDD as above; GTK pulse = accent-soft border/name flash with `GLib.timeout_add` (600 ms ×2), pointer = a fixed overlay Gtk.Image drawn at target allocation, ~1.5 s, one active pulse (newest replaces), ` Gtk.Settings gtk-enable-animations`/reduced-motion respected. Commit `guided: pulse + pointer + hand-off router`.

### Task 5: Overview = verdict + group cards + Needs you

**Files:** Modify `ui/console.py` (`OverviewPage` rebuild: `build_overview(win)` returns (content, dock_groups)); Test: re-root `tests/test_gw206_one_decision_list.py`, new pins in `tests/test_overview_v3.py`

Content: verdict strip (ok/warn + counts + snapshot age), three group cards (Care/Defense/System) each clickable → `handoff` to the group's page, 7-day bar chart (Gtk.DrawingArea, thin bars, one axis, tooltip), "Needs you" list (only items with buttons; each row = label + primary button + `handoff`). Dock: Snapshot refresh/auto, Trend (24h/7d), Ask-about. Bug-9 law pin rides here: with no needs-you rows, the section AND its title hide (`assert not overview.needs_you_box.get_visible()` when empty). Commit `overview: verdict + group cards + needs-you (variant 3)`.

### Task 6: Activity Log = one table + tabs + dock

**Files:** Modify `ui/auditlog.py` + `ui/window.py` `_LEGACY_PAGE`; Test: `tests/test_hunter_page.py` re-root + `tests/test_log_v1.py`

Tabs Everything/Decisions/Blocks/Findings wired to the existing three-tab page's data; rows carry producing-tool actions (psad→Block/Unblock, appfw→Allow rule/Block rule, rkhunter→Update baseline, aide→Review diff through its own lane); blocks-per-hour strip below (Gtk.DrawingArea, 24 thin bars, peak labeled); dock Filter/Sources/Actions. gw215-equivalent badge pin recreated here later (Task 16). Commit `logs: one table + tabs + dock (variant 1)`.

### Task 7: Firewall = fw-A + decisions card + Unblock-on-row

**Files:** Modify `ui/defense.py` — `DefenseView.refresh`/`_paint_armor` GO OFF THE UI THREAD (`GLib.add_timeout` + worker thread, page paints instantly — VISUAL-PLAN-UI §2 mandatory); decisions-waiting card with Keep/Delete/Restore; blocked table with Unblock per row; CVE rows REMOVED here (→ Task 10 Protections). Test: `tests/test_gw207_defense_rebuild.py` + timing pin `test_defense_show_runs_no_subprocess`. Commit `firewall: fw-A + threaded armor paint`.

### Task 8: Threat Hunter = finding cards + wired actions

**Files:** Modify `ui/hunterview.py`; Test: extend `tests/test_hunter_page.py`

Rule→action map next to `_RULE_CHANNELS`: malware-detected→`Delete now` (responderd quarantine lane deletes; quarantine = undo; ledger records path+hash), rootkit-warning/scan-positive→`Update baseline` (`--propupd`) + Re-run in Scans (handoff to scans prefilling `_SCAN_ACTIONS`), all→Ignore forever (quieted_ids keyed `(rule, subject)` — engine change in `hunter/store.py`), Ask, Dismiss. Resolved findings render one honest line. Test pins: "every rule kind has its action wired" + "ignore-forever keys rule+subject". Commit `hunter: th-A cards, permafix actions, rule+subject suppression`.

### Task 9: Tools = t2 cards + in-card config editor + permafix loop

**Files:** Modify `ui/toolsdesk.py` (+ new `ui/toolcontrol.py` for the editor lane); Test: `tests/test_tool_control.py` (new)

Card anatomy (full-width): header (name, logo, status dot), lifecycle row (start/stop/restart/run-now through the existing apply/polkit lane), schedule row (shown + editable → writes the tool's timer), settings fields row, and "Open config": expands in-card editor ((Gtk.TextView) loading the REAL config file (rkhunter `/etc/default/rkhunter` + `.conf` path map), Validate (line-level: key=value shape + known-key check from `TOOL_CONFIGS` map) then Apply via polkit lane, then offer baseline refresh (rkhunter `--propupd` / aide `--update`) with Yes/Later — Yes runs it and states the result on the card. Test pins: editor loads real file path, validation rejects unknown key with honest error, apply produces `applied` state + baseline offer, lifecycle buttons disabled while an operation is in flight. Commit `tools: t2 cards, validated config editor, permafix loop`.

### Task 10: Scans = s2 + Protections = p1

**Files:** Modify `ui/scanview.py` (mode cards Quick/Full/Deep + console + dock: boot-sweep schedule editable + throttle `nice/ionice/slots`); Modify `ui/protectdesk.py` (advisory strip + PATCH ADVISORIES = the `cve_rows` reader moved from defense.py, patch button → apt lane, coverage %, watch stamp; run cards); Test: re-root `tests/test_gw208_console_services.py`-family, new `tests/test_protections_p1.py`. Commit `scans: s2 modes; protections: p1 advisory wall`.

### Task 11: Harden = h1

**Files:** Modify `ui/harden.py` — score bar (Gtk.ProgressBar band-colored `%`), flat self-applying checklist rows (each row's primary button executes through polkit lane and restates the row); profile selector dock (recommended/strict/paranoid reshapes list); Test: `tests/test_harden_shell.py` re-root + `tests/test_harden_h1.py` (row apply states the result). Commit `harden: h1 score + self-applying checklist`.

### Task 12: Settings = st2 + Help = he1

**Files:** Modify `ui/settingsdesk.py` (group nav list: Appearance/Behavior/Assistant/Notifications; the tunables: voice, rail %, dock %, auto-jump, refresh, notifications); Modify `ui/helpdesk.py` (walkthrough headline — replays guided entries page-by-page via `guided.py`; doc-digest library reading `doc/tool-digests/*.md`; dock About + assistant brain state). Tests: `tests/test_settings_depth.py` re-root, `tests/test_help_walkthrough.py` (walkthrough iterates every rail page; digest list non-empty). Commit `settings: st2 groups; help: he1 walkthrough + digests`.

### Task 13: Assistant two tiers + GPU toggle

**Files:** Modify `ui/homepage.py`/`ui/assistant.py` (+ `assistant/llm.py`); Test: `tests/test_assistant_tiers.py` (new)

- Heuristic tier (default, always available): answers from status.json facts, findings' canned reasons (existing `assistant/explain.py` lanes), `doc/tool-digests/*.md` (loaded per-tool on demand), settings introspection. No model load — pin: `assistant.never_loaded_on(window_open)`.
- GPU toggle button in the assistant panel: off → "Enable GPU model" → loads `local gguf` with `n_gpu_layers` set, STAGED PROGRESS (weights → offload → warmup; a real Gtk.ProgressBar fed by chunks, not a spinner), then stays resident; click again = "Disable GPU model" → unload + VRAM release (llama `del` + gc). NEVER auto-loads on window open/actions/timers: assert `load()` is called only from the toggle handler (`tests` instrument `assistant/llm.py:load`).
- Model loading moves OFF the UI thread (worker + progress pulses). Commit `assistant: heuristic tier + owner-toggled resident GPU model`.

### Task 14: Doc digests — build-time corpus

**Files:** Create `tools/build_digests.py` + `doc/tool-digests/*.md` (committed); Test: `tests/test_doc_digests.py`

Curated sheet per tool (what its warnings mean, command surfaces, heuristics: when to baseline-update, allow vs block) + man-page digests compressed via the greysearch RAG lane at build time (`tools/build_digests.py` shells out to the EXISTING local RAG/kb ingester the owner built — no ollama; if the RAG tool is unavailable the build falls back to the curated sheet with an honest `NOT COMPRESSED` marker). Tests pin: digest file exists per tool in `DIGEST_TOOLS`, each ≥ 20 lines, contains "HEURISTICS:" section, and no digest names ollama. Commit `docs: per-tool digests (curated + RAG-compressed)`.

### Task 15: Fix-wave carry-over pins

**Files:** Modify `ui/window.py` (badge reads the ONE published pending list — same source `decisions.jsonl` published count the gate/drawer render; whole-file fallback stays behind `daemon unpublished` state), recreate `tests/test_gw215_badge_one_list.py` against the new sources; re-root `tests/test_gw211_ui_errors.py` (empty section laws per page). Commit `fix carryover: one-list badge + empty-section laws re-pinned`.

### Task 7a (fit-law sweep): every shipped page FITS the window

The owner's 2026-11-10 law (spec amendment): whole-page scroll is deleted;
pages fit the window; only inner containers scroll (event table, console,
in-card editor); wizard and dialogs behave the same. Retrofit EVERY page
from Tasks 3-12 as they ship (per-page ScrolledWindow wrappers removed;
sections compress/share width at 1080p with rail + dock present), then
pin each page: `tests/test_fit_law.py` sweeps all `_builders` with a
viewport of rail+dock+1080p height and asserts the page's top-level stack
has no outer ScrolledWindow and its natural layout height fits, with
inner lists allowed their own scrollers. Wizard dialog included. Done at
Task 16 with the screenshots (1080p check at the real window size).

### Task 16: install + screenshot verification (open Python, no Cython)

**Files:** install the plain-Python tree into `/opt/greywatch` (owner runs the guarded `~/tmp/gw-deploy-fixwave.sh`, updated 2026-11-10: excludes `*.so`, deletes stale compiled twins from the installed tree, keeps the legacy-UI fingerprint guard until the rebuild ships); after the install the fingerprint guard's legacy phase is retired in a follow-up owner-approved flip; screenshot each page at the owner's real window size (HiDPI) with the 1080p fit-law check (Task 7a) and verify rail 5% + every page's dock pulse. Owner verdict gate before calling done.

**OWNER LAW (2026-11-10): no Cython anywhere in this project — open readable Python is the deliverable.** Every instruction in this plan that says "run ./build-cython.sh after edits" is DELETED; tests import .py sources; the shipped tree contains no .so.

---

## Execution notes

- Tasks 5–12 each end with a screenshot of the rebuilt page (GTK grab script in `tools/` per existing manual-driver patterns) before commit.
- The visual companion mockups referenced in this plan live in `.superpowers/brainstorm/1813371-1794274193/content/` for visual reference during implementation.
- The old plan `VISUAL-PLAN-UI.md` remains as background; where they conflict, the round-2 spec wins (per header).
