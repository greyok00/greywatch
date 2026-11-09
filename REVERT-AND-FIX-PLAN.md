# HANDOFF: revert the local install and fix the 0.3.0 release bug

Written 2026-11-09 ~03:00 MST for whoever continues (human or another
agent). Read the EMERGENCY block first. The machine this was written
on is `grey@parrot` (Parrot Security 7.4, Python 3.13.5, user `grey`,
repo checkout `~/greywatch`).

## 0. EMERGENCY: revert the installed GreyWatch now

The installed 0.3.0 deb (built for this machine's Python 3.13) starts
a daemon that crash-loops against the real root-owned data. The
0.1.28 deb ran fine for weeks. Revert with:

```bash
sudo apt install -y --allow-downgrades /home/grey/greywatch/dist/greywatch_0.1.28_amd64.deb
sudo systemctl restart greywatch.service
systemctl --user restart greywatch-ui.service 2>/dev/null; true
sleep 60 && systemctl is-active greywatch.service
dpkg -s greywatch | grep Version   # must say 0.1.28
tail -2 /var/lib/greywatch/events.jsonl   # timestamps must be fresh
```

Then capture the crash evidence (this is the key file, paste its
contents back to the maintainer):

```bash
sudo journalctl -u greywatch.service --since "2026-11-08 23:00" --no-pager > /tmp/gw_crash.log
wc -l /tmp/gw_crash.log
```

The 0.1.28 deb is verified (sha256 in
`dist/greywatch_0.1.28_amd64.deb.sha256` matches). The postinst re-arms
the 0.1.28 daemon the way it always did; `/var/lib/greywatch` state is
untouched by a downgrade (no migration was ever needed).

## 1. What is actually broken (evidence already gathered)

- `dpkg` says 0.3.0; `systemctl is-active` flip-flops between `active`
  and `activating` (crash loop, `Restart=always`, `RestartSec=5`).
- `/var/lib/greywatch/events.jsonl` stopped growing at 23:49:46 while
  status shows "appfw engine armed" pairs every ~40 s: the 0.3.0
  daemon dies ~40 s after each boot, systemd restarts it, and each
  boot re-arms the appfw engine - that is the back-to-back
  notification spam the owner saw.
- `/var/lib/greywatch/status.json` is written only up to 21:54 (the
  last pre-install 0.1.28 cycle): the 0.3.0 daemon never finishes a
  `write_status` cycle, so the window renders from a stale snapshot -
  that is the degenerate layout (one huge wide pane, rail reduced to
  four items, third pane blanking the menu).
- The event ledger sits at ~188k lines against the new 20000-line cap;
  the trim is an hourly pass and the daemon dies every 40 s, so it
  never runs.
- 44 junk pending-decision specs (title "?", ts literally "ts") sit in
  `decisions.jsonl` from before tonight; they may be what breaks the
  third pane's render.

The traceback in `/tmp/gw_crash.log` names the crashing line. The
prime suspect: `greywatch_daemon.py`'s trim/scan path running as root
against the real 188k-line ledger (the trim reads `events.jsonl` and
rewrites through a `.root-tmp` stage inside `/var/lib/greywatch`); a
failure there must not be fatal but evidently is.

## 2. The rule going forward (why this happened)

Every gate that passed tonight (1848 unit tests x4 runs, lint zero,
three CI runs on the compiled tree) never exercised the daemon as
root against the real state dir. The bar for any future install:

- Reproduce the crash FIRST in a sandbox that mirrors root reality:
  copy `/var/lib/greywatch` to a temp dir, run the 0.3.0 daemon's
  `run_once` (and then `run_forever` for 3 cycles) AS ROOT against the
  copy (sudo python3), with the real ledger size. Only a pass there
  earns an install.
- Add a pinned root-shaped soak test (real-size ledger, root uid) to
  the suite so the case can never regress silently again.
- The UI must never render a degenerate window off a stale snapshot:
  make the shell show its "snapshot is stale, waiting for the daemon"
  state when `status.json` is older than the 90 s contract instead of
  painting half a layout (this matches the doctor's own `service` row,
  which said exactly that in the live snapshot).

## 3. Repository and release state (all committed/pushed)

- GitHub: https://github.com/greyok00/greywatch
  - `master` at `adeb989` + the ABI-note README commit (`1754c88`):
    everything current.
  - Tag `v0.3.0` at `c9393f4`; release
    https://github.com/greyok00/greywatch/releases/tag/v0.3.0 with
    wheel/deb/tarball + per-artifact sha256 (CI-built, provenance
    attested) and the container on ghcr (`v0.3.0` + `latest`).
  - IMPORTANT ABI FACT: the release-page deb is compiled for
    cpython 3.12 (the CI runner) and apt REFUSES it on 3.13 machines
    by design (`Depends: python3 (<< 3.13)`). The local recut for this
    machine (cpython 3.13) is `dist/greywatch_0.3.0_amd64.deb` - the
    one that is installed and crash-looping. Do not install either
    again until the root-shaped soak passes.
- Local commits map (newest last, all pushed):
  `01165c8` cannot-fail sweep -> `deaac97` F1-F5 extraction ->
  `97dc11e` release scaffolding -> `36ea0b7` gate hygiene ->
  `ee25200` learning-ledger GW-02 hardening -> `d513eb3` pinned soak
  -> `37cccb6` ITER-0004 doc fixes -> `85220d5` badge 1848 ->
  `56a4e78` changelog released -> `59eb7c1` geoip seam (release-CI
  fix) -> `0c129f3` ruff-zero lint pass (REBUILT ALL 109 TWINS after
  the fact; the four UI twins console/helpdesk/settingsdesk/shell were
  caught stale post-release by the twin audit) -> `adeb989`+
  `1754c88` README truth pass.
- Release-CI defects fixed en route: geoip test seam
  (`ui/identity.py::_geo_table`), 40 ruff findings, the workflow's
  container leg needed a `GH_PACKAGES_TOKEN` secret (GITHUB_TOKEN
  cannot write a user-owned container package).

## 4. Standing rules of this repo (enforced, do not skip)

- Cython twins: every `*.py` edit in a twinned package is invisible to
  tests and the runtime until its `.so` twin is rebuilt (single-module
  build ~30 s using `build-cython.sh`'s body). After any edit, rebuild
  BEFORE running tests or packaging.
- Push gate: pushes go through `git auth-push` (one-shot, 10 min) then
  `git push` within the window. Never push without it.
- Never release without an explicit owner instruction (tonight's
  release was owner-authorized: "update the github release").
- `docs/superpowers/` and `SESSION-MEMORY-0.3.0.md` are
  git-ignored/local except where committed; don't git add -f them.
- Artifacts live in `dist/`; the 0.3.0 set there is the LOCAL 3.13
  recut (22:38 build). The 0.1.28 set in the same dir is the safe
  revert payload.
- Shipped text carries no em dashes.

## 5. Where the full context lives (on this box)

- `~/greywatch/SESSION-MEMORY-0.3.0.md` - the whole session's memory,
  three addenda, commit chains, key facts, remaining owner items.
- `~/greywatch/docs/superpowers/` - the 1.0 requirements (IDs
  GW1.0-REQ/SCN), scenario cards, iteration records, evidence ledger,
  lane-to-evidence map (git-ignored by owner policy).
- `~/notes/` - slip-box with experience entries
  (`cython-twin-shadows-py-edits.md` explains the twin trap;
  `release-pipeline-defects-surface-publicly.md` explains tonight's
  class of failure).
- The 1.0 line's remaining owner items: REQ-031 (live service restart
  proof, needs sudo), REQ-051 (final approval). Everything else is
  MET on paper AFTER the root-shaped soak requirement above is added.
