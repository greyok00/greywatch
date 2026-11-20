"""Headless core: the modules the SERVICE and the CLI need.

These four used to live in ui/ and the root daemon imported them from
there, which made a privileged background service depend on a GUI package
for its trust list, its blocklist and its update checks. The files are
plain stdlib and never touched GTK, so this is a move, not a rewrite:
ui/<name>.py re-exports from here so every existing import keeps working,
while the service and the CLI now depend on the core, not the desktop.

Owner 2026-11-13: "work on the background service first, then the CLI...
all tools must work headless as a service and as the CLI, then we can
polish the GUI."
"""
