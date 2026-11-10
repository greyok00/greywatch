# DESIGN: GreyWatch UI rebuild — visual planner round 2 (amends VISUAL-PLAN-UI.md)

Written 2026-11-09 from the owner's directives in this session. Where this
document conflicts with VISUAL-PLAN-UI.md §1-2 (rail width, Overview as a
group heading), THIS file wins. VISUAL-PLAN-UI §5-§7 (page subjects, hunter
actionability, the warning loop, the resolve-everything law) carry forward
unchanged as part of this design.

## 1. The rail (owner spec, verbatim basis)

"see the entire menu on the left side and it's thin, like 5% width ...
large title headings: Overview, Care with Scans, Protections, Tools,
Harden nested, then Defense with Firewall and Threat Hunter nested, then
System with Activity Log Settings and Help nested."

Structure (groups = large title headings; children indented rows):

- **Overview** — title that IS the Home page (clickable heading).
- **Care**: Scans, Protections, Tools, Harden
- **Defense**: Firewall, Threat Hunter
- **System**: Activity Log, Settings, Help

Ten destinations, one subject each. Laws:

- The rail is ALWAYS fully visible from window open: every group heading,
  every child row, every badge. No collapse, no hide, no relayout on tick
  or click (`NARROW_RAIL`/`collapse_rail`/`rail_pinned` are deleted and
  `window._periodic_refresh` stops touching rail geometry).
- Width is 5% of the window's visible width (HiDPI scale included). The
  child label font sizes down until all ten children fit at that width.
  Labels never truncate, ellipsize, or hide. Settings exposes **Rail
  width** as an explicit tunable (slider, 5-10%, default 5%) — owner
  explicit-tunables law.
- Typography: group titles large (heading-weight), child rows compact
  with 14-16 px glyphs, generous vertical rhythm; current-row highlight
  by the theme's accent-soft, not a border.

## 2. One subject per page (carried, VISUAL-PLAN-UI §5)

Overview = "am I OK right now" (SuiteCard verdict + 4 stat tiles + recent
activity + chat below the feed). Firewall = access control (blocked,
decisions waiting, allow/block state) — the CVE wall moves to Protections.
Threat Hunter = the resident watcher's findings; scanner-tool outputs move
to Scans. Scans / Protections / Tools / Harden / Activity Log / Settings /
Help per §5. The owner's ten-page menu has no Watchlist row: Patch-the-
Planet coverage cards land on Protections (they are patch advisories),
browser-watch findings land on Firewall. Pages cross-link by button,
never by re-display.

## 3. Actionability (resolve-everything law, VISUAL-PLAN-UI §7)

Primary button on every row is the permanent fix: firewall popup ->
Allow/Block as a permanent saved rule; malware -> **Delete now**
(remove persistence, ledger path+hash, never execute; quarantine is the
undo lane); scanner warning -> **Update baseline** (--propupd / --update)
+ Re-run in Scans; blocked address -> Unblock; decision -> Keep / Delete /
Restore. Hunter findings wire rule->action per §5 map. Activity Log rows
carry the actions of whatever produced them. Resolution keys on
rule + subject so it stays resolved (no 72 h refire). Copy-text is never
a resolution.

## 4. Full tool control (owner decision: raw config included)

Each Tools-page card: lifecycle (start/stop/restart, run now), schedule
shown and editable on the page, real settings fields, and **Open config**
— an editor pane on the tool's real config file with validation and
Apply (writes through the existing polkit apply lane). After Apply, the
card offers the matching baseline refresh (rkhunter `--propupd`, AIDE
`--update`) — the permafix loop. The boot-sweep schedule surfaces on
Scans (VISUAL-PLAN-UI §6.5) and is editable like any tool schedule.

## 5. Assistant — heuristics tier + explicit GPU-model toggle (owner HARD)

"DO NOT LET IT USE OLLAMA ... HEURISTICS AND LOCAL LLM ONLY ... GPU
ENABLED LOCAL MODEL ONLY LIKE IT WAS BEFORE. DO NOT USE OLLAMA OR ANY
OTHER SERVER FOR CLOUD."

Two tiers, one toggle:

- **Default tier (always, no model).** Purely heuristic: answers from the
  daemon's canned reasons, the findings' structured facts, the docs corpus
  below, and settings introspection — logs, advice, man-page settings,
  next-step recommendations. Nothing loads. If a lane genuinely needs
  free-text generation without the big model, a tiny CPU-only gguf may
  serve that lane — never the GPU, never a server.
- **GPU model toggle.** An explicit assistant button ("Enable GPU model",
  states off → loading → on) loads the existing local gguf with GPU
  offload into VRAM *only when clicked*, with a full staged progress
  animation (weights → GPU layers → warmup, real progress not a spinner).
  It stays resident until the owner clicks it again to disable (unload,
  VRAM released). It NEVER loads on window open, on page actions, or on
  idle timers (the 2.6 GB RSS law). Chat beyond heuristics rides this
  model while on.

Docs corpus is LOCAL: curated per-tool cheat-sheets + heuristics in-repo,
plus man-page digests compressed once at build time through the
Greysearch RAG lane and shipped as plain files (`doc/tool-digests/`) the
assistant retrieves at ask time — both tiers read them. No server, no
cloud call, anywhere in GreyWatch.

## 6. Fix carry-over (the bug wave survives the rebuild)

Re-applied to the rebuilt pages with recreated pins: bug 8 one-list
badge (tray pill + broker badge read the ONE published pending list);
bug 9 hide-empty sections (Advisories / Action gate vanish when empty);
the gw211 pins re-root to the new page files; psad stderr probe and
appfw arm-wall live in the committed daemon. Warning-loop root causes
close via §3/§4 (baseline refresh paths now exist in-app; boot sweep
staggered and visible).

## 7. Testing

Recreated pins (gw215-equivalent badge pins, gw211 empty-section pins)
re-rooted to the new page sources; phases land per VISUAL-PLAN-UI §4
with the rail phase re-verified by screenshot at the owner's actual
window size (HiDPI included) before install; suite green each phase.
