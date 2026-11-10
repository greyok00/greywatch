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

### 1a. Main layout = three panes (owner pick, visual plan round 2)

Rail (left, §1) + page feed (center) + **fixed right control dock**
(~26% of content width). The dock groups ONLY the open page's controls —
filters, page actions, source toggles — in titled groups, one group per
subject. It never scrolls away with the feed and never auto-collapses.
Dock width is an explicit-tunable in Settings alongside rail width.
Entry pulse + pointer (§9 trigger 1) targets the dock's title. Pages
wider sections (charts/tables dockless) may span center+right when a
page declares it; that is per-page, never per-tick.

### Activity Log = variant 1 (owner pick, round 2)

ONE chronology table with a tab strip (Everything / Decisions / Blocks /
Findings) and a time-range control; every row carries the actions of
whatever produced it; a blocks-per-hour strip below the table; right
dock groups Filter (query + severity + tool + time), Sources toggles,
and Actions (live follow, export, clear resolved). On open the dock
title pulses with the pointer; a row that needs the user glows as the
hand-off target (§9 + Hand-off).

### Firewall = fw-A, Threat Hunter = th-A (owner pick, round 2)

Firewall: wall verdict strip on top ("wall up" + counts + psad live age),
"Decisions waiting" as its own flashing card (Keep / Delete / Restore on
the row), blocked-addresses table with Unblock-on-row, armor status as
one chip line (psad / nftables / arpwatch). Dock = Rules (allow/block
lists, add rule), psad knobs, Open-config buttons.

Threat Hunter: finding CARDS, each carrying severity icon + the rule
that fired + its real buttons per §5/§7 (malware: Delete now primary,
Quarantine as undo; scanner warnings: Update baseline + Re-run in Scans;
all: Ignore forever keyed rule+subject, Ask, Dismiss). Resolved findings
collapse to one honest line with the resolution stated. Dock = Filter
(severity/rule/state), Suppressions (rule+subject), Watcher (interval,
pause). The 72 h refire dies by construction (§6/§7).

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

### Theme (owner pick, visual plan round 2)

Two voices, ONE component set with two token sheets: **Graphite (dark,
warm charcoal, bone-white ink, warm-gray accent) is the DEFAULT; Paper
(light, warm off-white, ink accent) is the light voice.** The old
cyan/red dark accents are retired. A sun/moon toggle sits pinned at the
rail's bottom-left and swaps voices in one click; Settings also carries
the full voice/voice-related tunables. Categorical and status palettes
are validated per voice with the palette validator at build time.

### Overview = variant 3 (owner pick, round 2)

Verdict strip (ok/warning + counts + snapshot age) -> one health card
per rail group (Care / Defense / System), each with its own status line
-> the 7-day trend -> a **Needs you** section listing only items that
have buttons. Every item on the page is a button to its owning page
(pointer to the dock, never a re-display). Sun/moon toggle lives in the
rail's bottom-left on every page.

### Hand-off: the app sends you (owner addition, round 2)

Clicking any item on a card deep-links to the owning page: page
changes, the correct dock opens, and the target row is highlighted
selected in the feed. When something IMPORTANT arrives that needs a
human decision (decisions waiting, HIGH findings), the app auto-navigates
the same way — once per item, with the pulse + pointer showing where it
sent you; the active rail row and a "came from Overview" breadcrumb
stay visible so you always know where you are. Auto-jump is a Settings
toggle (default on per owner directive); click-to-jump always works and
is unaffected.

## 8. Visual-first readability (owner directive 2026-11-09: "go for
visuals first ... bar graphs, tables, charts, images, animations")

Every page is a stack of visually bounded, TITLED sections (cards with
their subject in the card title), so a page reads by scanning its
section titles first. Graphics carry what prose-tables did before:

- **Stat tiles.** SuiteCard's row keeps four verdict tiles (tools online,
  pending decisions, blocked, findings HIGH) with hero numbers.
- **Bar graphs.** Findings per tool (which tool is the loudest), blocked
  addresses by cause category, decisions waiting by age bucket. Vertical
  thin bars, data-end labels on the top bars only, one axis.
- **Trend lines.** Overview and Activity Log: findings/decisions/blocks
  as a 24 h / 7 d line chart, one measure per panel (never dual axis),
  2 px lines, hover tooltip naming the value and time.
- **Tables.** Blocklist, decisions, events: the detailed rows, sortable,
  with the §3 action buttons on each row.
- **Images.** Tool cards carry each tool's logo/glyph; findings carry a
  severity icon beside the status color (never color alone).

Chart laws (applied, from the dataviz discipline): form follows the
data's job; status colors (ok/warn/fail) are reserved for state and
ship with an icon + label; categorical hues come in a fixed order
derived from the theme's tokens and are VALIDATED at build time with
the palette validator against the theme's surface in both light and
dark voices; every chart has a table toggle; text wears ink tokens,
never series color. Tables and charts both exist for the same data —
the chart is the read, the table is the audit.

## 9. Guided attention (owner example: "logs page ... right-side control
menu ... flash highlight the title of that area or a pointer arrow")

Two primitives, built once, reused everywhere:

- **Highlight pulse.** A section's card title flashes with an accent-soft
  glow (about 600 ms, twice), then settles. Never re-fires on the same
  target within a cycle.
- **Pointer.** A small arrow appears pointing at the target area, holds
  about 1.5 s, fades. Drawn on the app surface so it can point at any
  card, rail row, or button.

Triggers:

1. **Page open.** Opening a page pulses its primary section and points
   at the control area that acts on that page's subject (the owner's
   example: click Activity Log -> the right-side control menu's title
   pulses and the arrow draws the eye to it). Every page declares its
   own entry target.
2. **Something arrives.** A new finding/decision/block pulses its
   section and row; the rail's group title pulses once; the badge ticks.
3. **An action completes.** The row/section that changed pulses and the
   result line states what happened ("Allowed chrome — rule saved").
4. **Guided walkthrough.** Help page can replay a first-visit sequence:
   per page, each control area highlighted in order with the pointer —
   the app teaches itself to the user.

Rules: animations are short and interruptible, respect the system
reduced-motion setting, never block input, never overlap each other
(one active pulse at a time, newest wins). Each page's entry-target
declaration is pinned by test (pulse fires on open; pointer targets the
declared control), and verified by screenshot.

