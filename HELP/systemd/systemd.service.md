# systemd.service — digest + LIVE findings (systemd 252+)

Raw: systemd/systemd.service.html (freedesktop.org). Consulted before unit
changes; findings below are VERIFIED LIVE, not recalled.

## Verified on this machine
- **226/NAMESPACE (exit before exec)**: `ReadWritePaths=` naming a
  not-yet-existing directory (/run/greywatch) fails the mount-namespace
  setup step → exit 226, NO code runs, `Restart=always` churns forever.
  Journal signature: "Failed to set up mount namespacing: <path>: No such
  file or directory" + "Failed at step NAMESPACE".
- **RuntimeDirectory=<name>** creates /run/<name> pre-namespace with correct
  perms and removes it at stop — the right way to have a runtime file.
  CAUTION: two units sharing RuntimeDirectory=<name> → the LAST one to stop
  removes it (the watchdog must NOT use it; it only reads).
- **WatchdogSec=/sd_notify** is the systemd-native alternative to our
  heartbeat file + watchdog timer; the master prompt prescribes the file
  (implemented literally). Revisit if the timer races the daemon boot.
- **Restart=always** + RestartSec=5: turns ANY clean quick exit into a
  paced loop; it saved nothing during 226 (no exec attempted) but revealed
  NRestarts as the churn meter.
- **Status codes**: 226/NAMESPACE = sandbox setup failure (systemd-side),
  NOT a program failure; distinguish from the program's own exit codes.

## Where the live unit lives
The shipped unit template (doc/greywatch.service, installed by install.sh)
is the source of truth for limits and sandboxing; the README documents its
effective resource caps. Namespace/sandbox changes follow the
re-tighten protocol: one directive per attempt, verify with
systemctl show + an uptime watch, then the next.