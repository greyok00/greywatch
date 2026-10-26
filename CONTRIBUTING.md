# Contributing

Thanks for looking at greywatch. It is a single-machine, root-privileged
security tool, so a few disciplines are stricter here than usual.

## The three rules this repo will not bend

1. **Privilege is a list, not a mood.** Only scripts listed in the
   installed polkit policy can be privileged, each helper is pinned to
   exactly one path, and helpers validate argv, back up before writing,
   and roll back. Any contribution touching `apply/` must keep those
   properties and add tests for them.
2. **The app firewall fails open.** A dead engine may never lock traffic
   out. Changes to `appfw/` need a test that keeps that guarantee true.
3. **No runtime network fetches** by the suite's own code. Reference
   material lives pre-fetched in `HELP/`; the machine may be offline.

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
python3 -m pytest tests/ -q        # headless: GUI modules skip honestly
```

The four display-dependent GUI test modules need a real GTK 4 display and
skip cleanly without one (`Gdk.Display.get_default() is not None` is the
probe — do not "fix" it back to `Gtk.init_check()`, which lies headless).
PyGObject + GTK 4 typelibs (`python3-gi`, `gir1.2-gtk-4.0`) are needed for
a full-fidelity run; CI installs them.

Before every push: `ruff check .` and `python3 -m pytest tests/ -q`.
The compiled `.so` path is exercised by `./build-cython.sh`; compiled
artifacts stay out of git.

## Commit and PR style

- Commit subjects: `area: change` in lowercase, one line that can be
  quoted back honestly ("who can verify this from the diff alone?").
- PRs must state blast radius (which units/tools the change can affect)
  and list the tests that prove it. If the change touches privilege or
  the event store, say so in the first line.
- Keep user-facing strings short and in plain words — they are shown in
  the app and asserted by tests.

## Reporting instead of fixing

Security issues follow SECURITY.md's private channels, please — a public
issue with root-privilege details is itself a disclosure.