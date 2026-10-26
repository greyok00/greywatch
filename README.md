<div align="center">
  <img src="doc/images/greywatch-banner.png" alt="greywatch — one dashboard for every protection on this Linux machine" width="720">
  <p><b>greywatch</b> — an endpoint security suite for one Linux machine:
  a root-privileged watchdog daemon, a stdlib CLI, and a GTK 4 desktop app
  that puts all 17 real security tools on the box under one plain-English
  dashboard.</p>
  <code>python3 cli.py status</code> on a protected machine, live:
</div>

```text
greywatch status — updated 2026-10-26T09:06:20+00:00  [10318921 dropped]
🟢 aide          GREEN  — AIDE (integrity check)
🟢 appfw         GREEN  — App Firewall
🟢 arpwatch      GREEN   last:2026-10-25 — Arpwatch (ARP monitor)
🟢 clamav        GREEN   last:2026-10-26T06:54 — ClamAV (antivirus)
🟢 fail2ban      GREEN  — Fail2ban (bans)
🟢 ufw           GREEN  — UFW (firewall)
🟢 yara-watch    GREEN  — YARA Watch (realtime scanner)
🟢 … every row has the same shape: dot, tool, state, last activity
```

## What it does

Every machine already runs protections it can't see at a glance — the
firewall, malware scanners, an intrusion blocker, file-integrity and
rootkit audits, watchers of every kind. greywatch lines them up in one
place, says in words what each is doing, runs scans on demand or on
schedule, makes guided changes only on your press, and records everything
so it can be undone. It does **not** replace your tools with new daemons —
it points the ones already installed and reports on them honestly.

What you get, layer by layer:

| Layer | What it is | Where |
|---|---|---|
| L1 — watchdog daemon (`greywatch.service`, root, hardened unit) | follows every tool's real logs via inotify + journalctl, keeps one fresh status file, one event record; also runs the app-firewall engine | `greywatch_daemon.py` |
| L2 — CLI (`greywatch`) | `status · events · tail · log · decisions · rules · answer` — everything the window does, without the window | `cli.py` (stdlib only) |
| L3 — GTK 4 desktop app | Security / Tools / Harden / Settings / Logs / Help / Wizard, dark or light theme, tray icon | `ui/app.py` |
| App Firewall | OUR OWN per-process outbound firewall: one nftables table, one queue, one decision chain | `appfw/` |

Every decision — suite-native or appfw intercept — flows through ONE
pipeline: specs → one answer per event (`data/decisions.jsonl`) → an
allowlisted helper script via `pkexec`. Only scripts listed in the
installed polkit policy can be privileged, and each is pinned to exactly
one helper path.

## The screens

Security is the health table: one row per protection — colored dot
(green running, amber paused-by-you or waiting, red not running), the
state in words, and last activity. Pause/Resume on each row pauses the
real systemd unit where one exists.

Tools is the workbench: the protections as cards with an honest one-line
state under each, a quick-scan strip with a live progress circle, and a
short record of what just happened.

Harden is the guided-change flow: run baseline checks with plain-user
probes (a check that cannot run is reported CANT-CHECK — never a silent
pass), review the result cards, apply only what you approve through the
system's own privilege prompt — every touched file is backed up and
journaled before the change, and **Undo last change** reverts it.

The full walkthrough — every screen with real screenshots and a ten-question
FAQ — is [doc/help.html](doc/help.html); the same text lives in the app's
Help tab.

## The App Firewall

Per-process outbound control, built in-suite (the old external firewall
daemon was fully removed from the machine). The engine installs its own
nftables table (never the system firewall's), queues every NEW outbound
connection, resolves the initiating process from /proc, and decides
through one chain: trusted site → trusted program → permitted local
services → downloaded block list → learning mode → block-unknown →
explicit ask → default allow-once (fail-open). A dead engine means
pass-through — **it can never lock your traffic out**.

It is **off by default**; arming is a deliberate owner act in the app, and
requires `netfilterqueue` plus libnetfilter-queue headers — without them
the engine refuses to arm and nothing else on the machine changes.

## Architecture rules (the design's spine)

- **Event-driven only** — inotify tailers (with a 50 ms stat-poll to cover
  the known truncate(2) inotify gap) + one journalctl follower; no polling
  sweep of the machine.
- **One record of truth** — `data/events.jsonl` (root-written, owner-only),
  `data/status.json` (re-rendered fresh), `data/decisions.jsonl` (one
  answered decision per event).
- **Privilege is a list, not a mood** — G2.4/G3.7: parsers for root-only
  logs are canonical-flagged and revalidated; the pkexec policy allowlists
  exact helper paths; helpers validate argv, back up, roll back.
- **Caps, owner-ordered** — daemon `CPUQuota=10% MemoryMax=200M`; events
  trimmed at 20 000; GUI rows 2 000; the GUI idles under 150 MB.

## Install (single machine, owner password once)

```bash
sudo cp doc/greywatch.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now greywatch.service
sudo install -m 0644 apply/polkit/greywatch.apply.policy \
   /usr/share/polkit-1/actions/greywatch.apply.policy
```

Requirements: Linux + systemd, GTK 4 (PyGObject), Python 3.12+, ImageMagick
(optionally, for tray/menu icon work). The suite also drives the tools it
finds — fail2ban, ufw, clamav, rkhunter, lynis, aide, Tetragon, arpwatch,
auditd — and degrades honestly (CANT-CHECK / blank) where one is missing.

### Configuration

There is nothing to configure before first run, and no credentials to
enter anywhere in the design — the suite drives your machine's own tools.
The only names the code consults:

| Name | Who reads it | What it does |
|---|---|---|
| `GREYWATCH_UI_USER` | daemon | user account the GUI relaunches under |
| `GREYWATCH_USER_HOME` | registry | alternate HOME for runtime state |
| `GREYWATCH_HELPER_CMD` | tests | test-only helper override; never set on a real machine |
| `NOTIFY_SOCKET` | appfw engine | set by systemd for Type=notify |
| `data/` tree | everything | runtime state, root-owned, never shipped |

## Verify

```bash
systemctl is-active greywatch
python3 cli.py --version             # version reads pyproject.toml
python3 cli.py status
python3 cli.py events | head         # root only: the event store is 0600
```

CI runs lint + the same test battery on every push; the display-dependent
GUI modules skip cleanly when no real display exists.

## Testing discipline

`tests/` carries 683 tests as of 2026-10-25: the copy rules live as tests
(`runbooks/longtext.py` flags user-facing strings over 12 words), wizard
flows are tested end-to-end with fakes, the theme system round-trips, and
the GUI has a smoke suite that builds every view headlessly first. The
Harden path is unit-tested never to escalate privileges by itself.

## Honest limitations

- The engine's process resolution is /proc-based (no eBPF): rare connection
  bursts may see brief resolve misses that fall back to allow-once; the
  queue rule's `bypass` guarantees a dead engine can never lock traffic out.
- Reverse DNS fills `dst_host` best-effort so site trust applies; an
  unresolvable IP decides on IP/path rules only, never on a guess.
- Truncate + same-length rewrite fully inside one 50 ms poll is
  undetectable by content-free means (GNU tail -F shares this).
- Disk encryption is ignored entirely by this build — never probed,
  never touched.
- Single-ban fail2ban events do not ask for decisions — only near-ignoreip
  patterns (3+ re-bans of one IP inside 300 s) do.

## License

Apache License 2.0 — [LICENSE](LICENSE). Contributions land under the same
terms ([CONTRIBUTING.md](CONTRIBUTING.md) is the front door), and
[ACCEPTABLE_USE.md](ACCEPTABLE_USE.md) is the boundary: defensive use on
machines you own or are authorized to administer, nothing else.

### Free vs premium

Everything in this repository is free and stays free — daemon, CLI, GTK
app, and the tagged release bundles. A future premium tier (extra
hardening profiles, hosted summaries) will live in a separate private
repo: the free core is never a trial of it, and payment, license-check,
and webhook secrets have no place in this tree — pre-commit and CI run
gitleaks on every push to keep it that way.

## Roadmap

- **v0.1.x** — documentation polish: real desktop screenshots replace the
  text-only walkthrough (release art set in progress).
- **v0.2** — packaging: a `.deb` that installs units + pkexec policy in
  one step.
- **premium (separate repo)** — hosted summaries and extra profiles; the
  free core is untouched by it.

<div align="center">
  <img src="doc/images/greywatch-icon-128.png" alt="greywatch icon: shield + watch face, GW" width="96"><br>
  <sub>greywatch — shield + watch: protections you can see, changes you can undo.</sub>
</div>