# greywatch — the suite itself (internal)

No man page for the assistant topic; curated from the repo docs, stored in gw-tools.

WHAT IT IS: Endpoint monitoring and hardening for the Linux desktop.
Components: greywatch_daemon (publishes /var/lib/greywatch/status.json,
keeps events.jsonl, owns the decisions gate), the resident hunter
(publishes findings every watcher cycle by reading the tools' logs),
scan_session.py (scanner schedules + throttling), responderd
(quarantine/decision enforcement), the plain-source UI (open readable
.py everywhere - the owner law is no compiled twins; entry points
ui/app.py and ui/tray_helper.py are plain), and the apply/polkit
privileged lane.

HEURISTICS:
- status.json drives the UI: older than 90 s means "Waiting for the
  daemon", never a full-looking layout painted from a stale file.
- Every finding row carries its REAL action (Delete now / Update
  baseline / Re-run / Allow / Block / Keep-Delete-Restore); "copy text"
  is never a resolution.
- Suppression keys (rule, subject) so resolved items never refire — the
  72-hour warning loop is dead by construction, not by hiding.
- The boot sweep arms scanners one-per-slot; the Scans dock owns that
  schedule, visible and editable.
- Data dirs: /var/lib/greywatch (root state) and ./data (checkout state,
  GREYWATCH_DATA_DIR override). The daemon reads the ledger with caps
  pinned in tests; the UI never scans the whole event file per tick.
