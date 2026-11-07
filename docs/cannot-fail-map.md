# The cannot-fail map

Every task lane in the program, what it does by default, what happens
when its IO fails, which health signal names the failure, and the test
that pins the contract. Nothing on this map is allowed to read a blur
as safe: where a lane cannot answer, it says so (`UNKNOWN` in the
watchlist, `NEUTRAL` in the doctor, `DEGRADED` in the digest), and it
never shows a green verdict over silence.

Owner directive 2026-11-07: "it cannot fail. It must have fail safes
and doctor mode/health ways to ensure it works and always completes its
tasks." This map is the deliverable (Wave E) that makes those fail
safes findable once, instead of living in thirty places inline.

## How to read this map

Each lane has five lines: its aspects, the standing default behavior,
the failsafe (what happens when the lane's read or write fails, with
the wave that built it), the health signal (a `status.json` key or a
doctor row the dashboard or `greywatch doctor` shows), and the pinning
test file. Start at your lane's block; the failsafe line tells you
what the code already does, and the pinning test tells you what will
catch it if it stops doing that.

## The lanes

**1. Scan runs** — the GUI's request file (`scan-request.json`), the
child scan session, the scan service's arm breaker.
*Default:* the daemon picks a well-formed request up within one cycle
and deletes it; malformed bytes are moved to `.rejected`, never
destroyed. The arm breaker paces re-arms at 30 s and opens after 3
fails in 5 minutes.
*Failsafe:* the daemon's scan runner never blocks the loop (its own
process, deadline-advances-before-work); a scan that cannot start says
why in the dashboard (Wave A) instead of a silent bare return.
*Health:* `status["scan_request"]` (`None`, or the file's present/age
facts - Wave C1); a request waiting over 90 s is `DEGRADED` in the
doctor's scan row.
*Pinned by:* `tests/test_gw215_scan_honesty.py`, plus the arm-breaker
breaker in the daemon's `run_forever`.

**2. Tool lifecycle / healer** — registry probes, supervision, the
healer's budgeted repairs.
*Default:* probe verdicts are READY / YELLOW / BROKEN with remediation
hints; the healer repairs with budgets and breakers, questions never
auto-fixes.
*Failsafe:* tool states the daemon cannot answer read "status not
available yet" (heartbeats) instead of a green guess.
*Health:* `status["tools"]`, heartbeat check-ins every 15 min.
*Pinned by:* the untouched healer/supervisor suites
(`tests/test_healer*.py`, `test_heartbeat*.py`).

**3. Block / unblock** — the blocked-IP ledger, the nft verify probe,
the re-arm sweep, the block reviewer.
*Default:* blocks are latched over restarts; a "block for good" that
fell out of the firewall is re-armed and announced once.
*Failsafe:* the verify probe fails OPEN - a block that cannot be
verified is never churned, and the uncertainty is LATCHED (Wave B3):
`verify_unsure` rides in the digest beside the note "block verification
could not run; blocks are left untouched" until the next good probe.
*Health:* `status["verify_unsure"]` + the defense digest note.
*Pinned by:* `tests/test_gw214_probe_honesty.py` (latch on, probe runs
clear, real verdicts clear, no churn).

**4. Quarantine / restore / wipe** — the file channel's three
irreversible-ish directions.
*Default:* quarantine is reversible, restore keeps the quarantine copy
on request, wipe confirms in a dialog every time.
*Failsafe:* none of the three channels can answer "empty" for an
unreadable file - questions never fix, unreadable never reads as safe.
*Health:* decision cards stay pending on any helper fault (Wave A1).
*Pinned by:* `tests/test_gw161_fixes.py`, `tests/test_gw168_169.py`
plus the record-tail guard in `tests/test_gw211_ui_errors.py`.

**5. Watchlist (Patch the Planet)** — the map download, per-machine
coverage matching, the coverage file, the announcements and the nightly
delta.
*Default:* coverage is matched only against what this machine's own
package channels report installed; an answered channel is the only
source, nothing is invented.
*Failsafe:* a channel that cannot be read travels as `probe_failed`
beside the coverage rows (Wave B2) - "empty" can never masquerade as
"nothing is covered": the defense page and the assistant both answer
UNKNOWN with the failed channel names.
*Health:* `ptp-watch.json`'s `probe_failed` key; the defense digest.
*Pinned by:* `tests/test_gw214_probe_honesty.py`,
`tests/test_ptp.py` (legacy list-compat pins untouched).

**6. CVE sync** — the cache download, refresh timing, and the active
rules evaluation.
*Default:* one announce per new HIGH+ flaw in a managed tool; the
digest and hunter read the same rules.
*Failsafe:* an unwritable announce ledger keeps the specs
retry-until-persisted (see lane 7); a failed cache fetch reads as
never-fetched, not zero.
*Health:* counts in `status["failures"]["cve"]`.
*Pinned by:* `tests/test_gw213_ledger_stall.py`
(`test_cverules_evaluate_uses_the_same_contract`),
`tests/test_cve*.py`.

**7. Announcements ledger** — one append-ledger per lane
(`ptp-announced.jsonl`, `ptp-delta.jsonl`, cve announce state).
*Default:* news is announced once and marked seen by the ledger write
itself - the write IS the de-duplication.
*Failsafe:* the 2026-11-07 Wave B decision: a ledger the disk refuses
SILENCES nothing and LOSES nothing - the specs stay in memory with
`.stalled` set (a list subclass, so legacy code cannot notice), the
same news repeats on the next pass until persisted, and the daemon
says why once per 600 s (Wave B1). Duplication while stalled is
visible and bounded; silence is permanent loss.
*Health:* one deduped YELLOW notice + `failures["ledger"]` count.
*Pinned by:* `tests/test_gw213_ledger_stall.py` (stall keeps specs,
recovery re-announces exactly once, daemon counting and dedupe), with
the replaced pins in `tests/test_ptp.py`.

**8. Assistant** — the chat ladder's read of this machine's facts.
*Default:* answers from the pack the daemon published; never-fetched
reads as never-fetched.
*Failsafe:* a package channel that could not be read answers UNKNOWN
with the channel names (Wave B2), never "nothing this machine runs".
*Health:* the answer text itself is the signal.
*Pinned by:* `tests/test_gw214_probe_honesty.py`
(`test_assistant_answers_unknown_when_channel_failed`).

**9. Helpers / polkit** — the helper batch, the one-decision record
tail, helper stderr routing.
*Default:* every helper decision is recorded in
`decisions.jsonl`; the record tail failing now keeps the card open and
says so (Wave A1).
*Failsafe:* helper failures carry the exit code and the last safe
stderr line (Wave A3) into every consumer's message; the exception
never escapes the callback.
*Health:* decision cards + `audit.record("decision", ...)` trail.
*Pinned by:* `tests/test_gw211_ui_errors.py`,
`tests/test_wizard.py`, `tests/test_buttons_functional.py`.

**10. Icons / themes** — the theme system literal CSS and image assets.
*Default:* missing assets fall back to the default theme; theme
switching is pure presentation.
*Failsafe:* theme load errors render the default palette; no lane
state is reachable from styling.
*Health:* none needed (presentation-only lane).
*Pinned by:* the theme suites (`tests/test_theme*.py`).

**11. Data file IO** — `status.json`, `events.jsonl` + outbox,
`doctor-last.json`.
*Default:* status.json is 0640 root:ui-group, written through one
atomic replace; the outbox buffers event lines and persists them
journal-style.
*Failsafe:* append failures keep the batch and pace the retry (Wave
B's daemon path); the 2000-line reclaim that throws OLDER lines away
during a write outage now COUNTS them (`outbox_dropped`, Wave B4) and
the fails band says "older event lines dropped during a write outage:
N". Lines that arrive during the flush are never counted as dropped.
*Health:* `status["outbox_dropped"]`, `status["dropped"]`,
`status["failures"]["write"]`.
*Pinned by:* `tests/test_gw214_probe_honesty.py`, `tests/test_gw202*.py`
(legacy compat).

## The health layer (doctor, Wave D)

The doctor is always on, not only after a manual run:

- Four honest service rows - `service` (the daemon's unit + the
  dashboard snapshot's age, with the dashboard's own 90 s contract),
  `scan` (what is waiting on the request channel), `firewall` (nft,
  `NEUTRAL` "cannot check as this user" when it cannot answer),
  `backlog` (pending decisions, `DEGRADED` above 20). A row that
  cannot check says `NEUTRAL`, never READY.
- The daemon builds the same rows every `write_status` cycle,
  publishes `status["doctor"]`, and persists `doctor-last.json`
  (0640, root:ui-group) beside status.json so the truth survives a
  daemon restart. The CLI run persists the same way, best-effort,
  with its exit code untouched (Wave D3).
- `python3 doctor.py --machine` prints a final `DOCTOR <n_red>
  <n_yellow>` line and exits 0 with no RED, 3 with any RED
  (Wave D1). `NEUTRAL` rows are neither - they are honest absences,
  not failures.
*Pinned by:* `tests/test_gw216_doctor_machine.py`,
`tests/test_gw217_doctor_snapshot.py`.

## Preserved decisions (the laws the waves did not touch)

- The verify probe reads fail-open: a block is never churned because a
  probe was blind (now with the uncertainty latch, Wave B3).
- Coverage never invents rows; UNKNOWN never becomes a verdict.
- Questions never auto-fix; unreadable never reads as safe.
- Deadline-advances-before-work: a raising write_status cannot pin a
  retry to the next 0.5 s pass.
- Dedupe windows (600 s) keep persistent failures from flooding the
  feed; every escalation rides `_notice`, never a bare print.
