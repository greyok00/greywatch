"""The threat hunter — a separate user-level process, by design.

The hunter investigates hypotheses over evidence GreyWatch already
collects (events, scan findings, downloads, imported HAR captures) plus a
few small, unprivileged web-activity sources. Every file it writes lives
under ``<data_dir>/hunter/`` and every file it reads from the shared state
directory is opened read-only, so a crash here cannot take the daemon, the
window, or the event store with it.
"""