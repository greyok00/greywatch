<div align="center">
  <img src="doc/images/greywatch-banner.png" alt="greywatch — running wolf" width="440">
</div>

# GreyWatch

GreyWatch collects the security tools already installed on a Debian-based
desktop — antivirus, rootkit scanner, integrity check, firewall, audit — into
one window, runs their scans in order, and adds an assistant that reads this
machine's own event log to answer questions about what they found.

Everything stays on your computer: no cloud, no account, no telemetry.

<div align="center">
  <img src="doc/images/assistant-blocked.png" alt="GreyWatch Assistant answering “Last block”: the newest refused connection, what a deny line means, the destination, and evidence tiles for the program and the server" width="900">
  <br>
  <sub>Asked “Last block” — the newest refused connection, read from this machine's own event log.</sub>
</div>

## Install

The release `.deb` and tarball are compiled for Python 3.12, the version
Ubuntu 24.04 LTS and Linux Mint 22 ship, along with the GTK4, PyGObject and
systemd they need. On a Debian-based release with a different Python, build
from a checkout (below) or use the wheel.

Download `greywatch_0.1.7_amd64.deb` from the
[releases page](https://github.com/greyok00/greywatch/releases), then install it:

```bash
sudo apt install ./greywatch_0.1.7_amd64.deb
```

The package installs under `/opt/greywatch`, enables `greywatch.service`, binds
the service to your desktop account, and adds the menu entry. Launch
**greywatch** from the applications menu, or run:

```bash
python3 /opt/greywatch/ui/app.py
```

To upgrade, install the newer `.deb` the same way. To remove it,
`sudo apt remove greywatch`; your event history stays in `/var/lib/greywatch`.
Each release includes a checksum file, so you can verify the download first:

```bash
sha256sum -c greywatch_0.1.7_amd64.deb.sha256
```

If you would rather build from a checkout, this route installs under
`/usr/lib/greywatch` and also fetches the optional assistant model:

```bash
git clone https://github.com/greyok00/greywatch.git
cd greywatch
sudo ./install.sh
sudo ./install.sh --check      # verify what was installed
python3 cli.py status
```

`sudo ./install.sh --uninstall` reverses it and keeps your history.

The wheel is for the command line only:

```bash
pip install https://github.com/greyok00/greywatch/releases/download/v0.1.7/greywatch-0.1.7-py3-none-any.whl
gw --version
gw status
```

It installs the `gw` command and the same code, but not the systemd unit,
polkit policy or icons. Use the `.deb` or `install.sh` for a system install.

## The assistant

Ask a question in plain words. The assistant answers from this machine's
event log — the same file the background service writes — so nothing is
invented and no question leaves the machine.

| You ask | You get |
|---|---|
| What program was blocked? | The newest block: program, time, destination (Cloudflare, Amazon, Google…), the firewall's verdict, and an evidence strip naming the binary |
| How do I fix the rootkit scanner? | What the warning means, why it matters, and numbered steps: copyable commands plus app actions |
| What needs attention right now? | Tools ranked by state, then recent HIGH and CRITICAL events, each with one next step |
| Why is ClamAV yellow when the events look fine? | The difference between a tool's health and its event history, and which one to act on |
| Turn on the app firewall | A confirm dialog; on accept the action runs and is recorded in `assistant-actions.jsonl` as `via=assistant` |
| Switch to the light theme | The theme changes, nothing else |

It can pause or resume a protection, start a scan, turn on the app firewall,
open learning mode, update lists, trust or block a site or program, switch
theme, and open a page. Every one of those actions pauses at a confirm dialog
and lands in the audit trail.

<div align="center">
  <img src="doc/images/assistant-light.png" alt="The same answer in the light theme" width="620">
  <br>
  <sub>The same answer in the Swiss (light) theme.</sub>
</div>

**The chat model is optional.** A Qwen3-1.7B model (about 1.1 GB, CPU only, no
network port, reasoning disabled) handles the wording that pattern matching
cannot. Without it, every question above still gets a deterministic answer
from the built-in advice engine. `sudo ./install.sh` fetches the model for
you. On a `.deb` install, add it with:

```bash
sudo python3 -m pip install --break-system-packages 'llama-cpp-python>=0.3.0'
sudo mkdir -p /var/lib/greywatch/models
sudo curl -L --fail -o /var/lib/greywatch/models/Qwen3-1.7B-Q4_K_M.gguf \
  https://huggingface.co/unsloth/Qwen3-1.7B-GGUF/resolve/main/Qwen3-1.7B-Q4_K_M.gguf
sudo systemctl restart greywatch
```

## Scans and the Security Tools page

The Security Tools page is where you start a scan and watch it. Six buttons run
scans: **Scan everything**, **Quick scan**, **Full antivirus scan**, **Rootkit
scan**, **Security audit**, and **File-integrity check**. They run one at a
time, in the order you asked for them. Each scanner starts as its own systemd
unit, so closing the window, or restarting the service, does not kill a
running scan.

Every scanner gets a full-width row with a horizontal progress bar, a counter
in the scanner's own units (files scanned, checks completed, temp folders
swept), and the last lines that scanner printed. A queued row says which
scanner it is waiting for, and a finished row keeps its log.

Findings sit above the tool rows, newest first. Each one shows the severity in
plain words, the tool that found it, the file when there is one, and a plain
reading of the raw line. Click it for a review dialog: what the line means,
why it matters, numbered steps, and, for a file, **Quarantine** and **Delete**.
Those run through a polkit helper that asks for your password and refuses
system paths. Routine notices — baseline drift, package debris, tool
suggestions — fold into a collapsed *expected, not errors* section, so a real
finding is not buried.

## The tools it manages

Seventeen protections, one registry. The app reads each one's state and logs,
runs its scans, and can pause or resume it without a terminal.

| In the app | Under it | What greywatch does |
|---|---|---|
| Antivirus | ClamAV | Full and quick scans, files scanned, every hit |
| Virus definitions | freshclam | Freshness check, on-request update |
| Rootkit scanner | rkhunter | Rootkit scans, warnings, hidden files |
| Security auditor | Lynis | Audit run, warnings with their test IDs |
| File integrity | AIDE | Integrity check, files changed since the baseline |
| On-access scanner | YARA Watch | Realtime scan of files as they are touched |
| Scheduled scanner | YARA temp scan | Sweeps `/tmp` and `/var/tmp` every 15 minutes |
| Firewall | UFW | State, and blocked-connection events |
| App firewall | greywatch's own | Per-program allow/deny for outbound and inbound traffic |
| Network watcher | greywatch's own | Light IDS over connection events |
| Intrusion blocker | fail2ban | Bans and unbans as events |
| Program jail | AppArmor | Policy denials (AVC) |
| System event log | auditd | Audit records, crashes, exec events |
| Auto-responder | greywatch's own | Quarantine or kill a flagged process |
| Program watcher | Tetragon | Kernel eBPF process and network events |
| WiFi watcher | arpwatch | New devices and address changes on your LAN |
| Update checker | greywatch's own | CVEs for installed packages |

## The rest of the app

The app firewall decides per program and asks before a new connection is
allowed. It has three modes. Standard asks once about an unknown program or
site and remembers your answer; an unanswered prompt follows your headless
choice and traffic keeps moving. Learning blocks nothing and records every
new connection, so you can see what a program needs before you allow it.
Whitelist connects only what you have allowed; if its worker is unavailable
for more than a few seconds it restores fail-open traffic so the machine
keeps its network, then re-arms when the worker returns.

Trusted sites and trusted programs can be set in Settings or by asking the
assistant, and the firewall consults both.

Endpoint Hardening checks the machine against a hardening baseline, shows the
real value behind each gap, and previews every change before anything is
applied. Applying takes one password prompt. Service changes are staged and
the page offers a restart when one is needed, so you keep working and restart
on your schedule. Controls marked advisory — a package backlog, the
firewall's front-end role — are explained and never applied for you.

Logs show every event newest first, filterable by tool, with the raw line
beside its plain reading. Settings covers appearance, the app firewall,
connections, this computer, diagnostics, updates, trusted sites and trusted
programs. Two themes ship: Obsidian (dark) and Swiss (light).

The `gw` command reads the same store the window does: `gw status`,
`gw events`, `gw tail`, `gw log`, `gw decisions`, `gw answer`, `gw doctor`,
`gw setup`.

## Where everything lives

| Path | What it is |
|---|---|
| `/opt/greywatch` | Program tree from the `.deb` |
| `/usr/lib/greywatch` | Program tree from `install.sh` |
| `/var/lib/greywatch` | State: events, status, scans, scan logs, models |
| `/var/lib/greywatch/scan-logs/` | Each scanner's own output, one folder per scan |
| `/etc/systemd/system/greywatch.service` | The root service unit |
| `/usr/share/polkit-1/actions/greywatch.apply.policy` | Allow-list for the helper scripts |
| `/usr/share/applications/greywatch.desktop` | The menu entry |

## Troubleshooting

**The window opens but every tool says UNKNOWN.** The service is not running,
or it is not bound to your user:

```bash
systemctl status greywatch.service
journalctl -u greywatch.service -n 50 --no-pager
```

If it is running, check the `GREYWATCH_UI_USER` line in
`systemctl cat greywatch.service`; it must name your desktop account. Fix it
with `sudo systemctl edit greywatch.service`, then restart the service.

**A scan sits queued and never starts.** See what units exist and what the
service is doing:

```bash
systemctl list-units 'gw-scan-*' --all
ls -la /var/lib/greywatch/scan-logs/
```

**A scanner finishes instantly and reports nothing.** The row now shows it as
a failure with the reason. The usual cause is a missing tool; the row names
it. Install it (`clamav`, `rkhunter`, `lynis`, `aide-common`) and run the scan
again.

**The assistant answers but never loads the model.** Run the three commands
under [The assistant](#the-assistant) and restart the service. Until then it
answers from the advice engine.

**Two program trees exist.** The `.deb` uses `/opt/greywatch`; `install.sh`
uses `/usr/lib/greywatch`. Keep one. Check what the service runs with
`systemctl cat greywatch.service | grep ExecStart`.

## Build and test

```bash
python3 -m pytest tests/ -q     # 1186 passing, 1 skipped
ruff check .
./build-cython.sh               # compile the modules (150)
packaging/build-deb.sh
packaging/build-tarball.sh
packaging/build-wheel.sh
```

A root daemon tails each managed tool's journal and log files, parses every
line into a structured event, and appends it to an `0600` append-only store.
It also runs the app firewall and publishes the status snapshot the UI reads.
The GTK4 app and the `gw` CLI are read-only clients of that store: the window
never needs root, and no scan asks for your password.

![Three layers: root daemon, CLI, desktop app](doc/images/arch-layers.svg)

The program lives in a root-owned, group/other-write-free tree; runtime state
lives in `/var/lib/greywatch` (`0770`, root plus your desktop group). Root
writes into the shared directory go through a private staging directory with
exclusive, symlink-refusing creates and one atomic rename, and helper scripts
run through a polkit policy that allow-lists exact installed paths. The
assistant has no network access and executes nothing on its own: every command
it offers is text you run, and every action pauses at a confirm dialog.

## License

Apache 2.0. Source, issues and releases:
[github.com/greyok00/greywatch](https://github.com/greyok00/greywatch).
