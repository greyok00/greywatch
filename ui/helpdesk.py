"""The Help page (wave D split; rebuild round 2 task 12): the
index-and-pane page, the walkthrough headline ("Show me around" with its
Start-the-tour button), the doc-digests library with its in-app reader,
and the About card. MainWindow inherits it unchanged."""
from __future__ import annotations

import os
import pathlib

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, GLib, Pango    # noqa: E402

from ui import metrics, guided
from ui.plain import escape, muted as pc_muted, soft as pc_soft
from ui.toolicons import icon_name as tool_icon

TOUR_MS = 1200          # one page at a time, ~1.2 s apart (he1)
TOUR_TEST_ENVS = ("GREYWATCH_XVFB", "GREYWATCH_TEST_DISPLAY")

# The walkthrough's page order: the home row, then every rail row in the
# rail's own RAIL order (ui.shell). A rail key that folded into a page
# (harden -> services) still routes through the window's legacy map, and
# each walked page pulses its declared entry dock group (guided.PAGE_ENTRY)
# through the route's own greeting - the walk never invents a target.


def tour_pages() -> tuple:
    """The walkthrough's route: overview, then the rail in RAIL order."""
    from ui import shell
    return ("overview",) + tuple(shell.RAIL_KEYS)


def digests_dir() -> pathlib.Path:
    """The committed digest corpus, listed where it really lives."""
    from tools.build_digests import DIGESTS
    return pathlib.Path(DIGESTS)


def _digest_description(path: pathlib.Path) -> str:
    """A digest's own first line, as its one-sentence description; an
    unreadable file names itself instead of inventing words."""
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip().lstrip("#").strip()
            if line:
                return line
    except OSError:
        pass
    return f"{path.stem}'s digest (its first line could not be read)."


class HelpDeskMixin:
    def _help_view(self):
        """Help as an index and a pane, matching Settings.

        The old page was one long column: a six-row key, seventeen
        protection cards in two columns, then ten questions and a command
        table — it ran on and lost its shape at the end. Each part is now
        its own section, one at a time, with nothing to scroll.
        """
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        page.set_vexpand(True)

        head = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        head.set_margin_top(metrics.PAGE_TOP)
        head.set_margin_start(metrics.PAGE_X)
        head.set_margin_end(metrics.PAGE_X)
        head.set_margin_bottom(14)
        head.append(self._h1("Help"))
        intro = Gtk.Label(xalign=0)
        intro.set_xalign(0)
        intro.set_wrap(True)
        intro.set_markup(
            f"<span size='13000' font_family='Inter' color='{pc_muted()}'>"
            "Every protection on this computer, in one place. Plain words "
            "here; raw detail is one click away.</span>")
        head.append(intro)
        page.append(head)

        body = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        body.set_vexpand(True)
        index = Gtk.ListBox()
        index.add_css_class("gw-index")
        index.set_selection_mode(Gtk.SelectionMode.SINGLE)
        index.set_size_request(190, -1)
        index.set_valign(Gtk.Align.START)
        index.set_margin_start(20); index.set_margin_end(12)
        index.set_margin_bottom(metrics.PAGE_BOTTOM)
        stack = Gtk.Stack()
        stack.set_transition_type(Gtk.StackTransitionType.NONE)
        stack.set_hexpand(True); stack.set_vexpand(True)
        stack.set_margin_start(12)
        stack.set_margin_end(metrics.PAGE_X)
        stack.set_margin_bottom(metrics.PAGE_BOTTOM)

        self._help_stack = stack
        self._help_index = index
        for key, icon, label, builder in (
                ("start", "help-contents-symbolic", "Using it",
                 self._help_start),
                ("docs", "documentation-symbolic", "Docs",
                 self._help_docs),
                ("tools", "applications-system-symbolic", "Security Tools",
                 self._help_tools),
                ("questions", "dialog-question-symbolic", "Questions",
                 self._help_questions),
                ("terminal", "utilities-terminal-symbolic", "Terminal",
                 self._help_terminal),
                ("about", "help-about-symbolic", "About",
                 self._help_about)):
            row = Gtk.ListBoxRow()
            row._key = key
            line = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=9)
            ic = Gtk.Image.new_from_icon_name(icon)
            ic.set_pixel_size(15)
            line.append(ic)
            name = Gtk.Label(label=label, xalign=0)
            name.set_xalign(0)
            name.add_css_class("gw-index-label")
            line.append(name)
            row.set_child(line)
            index.append(row)
            stack.add_named(builder(), key)

        def _picked(_lb, row):
            if row is not None:
                stack.set_visible_child_name(row._key)

        index.connect("row-selected", _picked)
        index.select_row(index.get_row_at_index(0))
        body.append(index)
        body.append(stack)
        page.append(body)

        # The dock's About group (he1): the version and the assistant's
        # brain state in one place the page's arrival greets.
        version = Gtk.Label(label=f"GreyWatch {self._version()}", xalign=0)
        version.set_xalign(0)
        version.add_css_class("gw-h2")
        brain = Gtk.Label(xalign=0)
        brain.set_xalign(0)
        brain.set_wrap(True)
        brain.set_text(self._brain_line())
        self._help_brain = brain
        return page, [("About", [version, brain])]

    # -- the walkthrough (he1) --------------------------------------------
    def tour_pages(self) -> tuple:
        """The walkthrough's route, bound to the window: the home row,
        then every rail row in RAIL order."""
        return tour_pages()

    def _brain_line(self) -> str:
        """The assistant's brain state, read through the assistant's own
        state seam when it exists (the rebuild's task 13 adds the GPU
        toggle); until then the honest static truth."""
        seam = getattr(self, "_assistant_state", None)
        if callable(seam):
            try:
                return " ".join(str(x) for x in seam() if str(x).strip())
            except Exception:            # noqa: BLE001 - the line is paint
                pass
        return "heuristics on · GPU model off"

    def _tour_autorun(self) -> bool:
        """First launch takes the walkthrough once; the flag lives in the
        settings file every tunable writes. A GUI-test window never
        hijacks the pages mid-run, so the walk gates on the test
        session's own environment markers."""
        if any(os.environ.get(e) == "1" for e in TOUR_TEST_ENVS):
            return False
        if not guided.load_toggle(key="tour_done", default=False):
            self._tour_start()
            self._tour_step()
        return False

    def _tour_start(self) -> bool:
        """Open the walkthrough: route state on the window and surface the
        Stop control in the header, where it survives page switches."""
        if getattr(self, "_tour", None) is not None:
            return False
        stop = Gtk.Button(label="Stop tour")
        stop.add_css_class("gw-mini")
        stop.set_tooltip_text("End the walkthrough; nothing else changes.")
        stop.connect("clicked", lambda *_a: self._tour_end(False))
        bar = getattr(self, "_header_bar", None)
        if bar is not None:
            bar.append(stop)
        self._tour_stop_btn = stop
        self._tour = {"pages": tour_pages(), "i": -1, "id": None}
        return True

    def tour_position(self) -> int:
        """Where the walkthrough stands: -1 before the first page."""
        state = getattr(self, "_tour", None)
        return state["i"] if state else -1

    def _tour_step(self) -> bool:
        """One page of the walk: route, greet, schedule the next. The
        route's own _show greets the page's declared dock group
        (guided.PAGE_ENTRY), so a walked page points where to look."""
        state = getattr(self, "_tour", None)
        if not state:
            return False                 # the walk ended or never began
        state["i"] += 1
        if state["i"] >= len(state["pages"]):
            self._tour_end(True)
            return False
        guided.navigate(self, state["pages"][state["i"]])
        old = state.get("id")
        if old:
            try:
                GLib.source_remove(old)
            except (RuntimeError, TypeError):
                pass                     # already fired
        sid = GLib.timeout_add(TOUR_MS, self._tour_step)
        state["id"] = sid
        if hasattr(self, "_glib_ids"):   # a destroyed window sweeps too
            self._glib_ids.append(sid)
        return False

    def _tour_end(self, completed: bool = False) -> bool:
        """End the walk, with or without finishing it: either way the
        one-time flag is written - the tour asks once for a boot."""
        state = getattr(self, "_tour", None)
        self._tour = None
        if state and state.get("id"):
            try:
                GLib.source_remove(state["id"])
            except (RuntimeError, TypeError):
                pass                     # already fired
        stop = getattr(self, "_tour_stop_btn", None)
        if stop is not None:
            parent = stop.get_parent()
            if parent is not None:
                parent.remove(stop)
            self._tour_stop_btn = None
        guided.persist_toggle(True, key="tour_done")
        return False

    # -- the digest library (he1) ------------------------------------------
    def _help_docs(self):
        """The doc digests the assistant reads, one row with a Read
        button each; the reader is an honest in-app window with its own
        inner scroll (the page-fit law holds: the page never scrolls)."""
        card, inner = self._settings_card(
            "Doc digests",
            "What the assistant reads about each tool, as plain text. "
            "Read opens it here; nothing outside the app.")
        for path in sorted(digests_dir().glob("*.md")):
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
            row.add_css_class("gw-help-row")
            words = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
            words.set_hexpand(True)
            name = Gtk.Label(xalign=0)
            name.set_xalign(0)
            name.set_halign(Gtk.Align.START)
            name.set_markup(f"<span size='13000' font_family='Inter' "
                            f"weight='600'>{escape(path.stem)}</span>")
            words.append(name)
            desc = Gtk.Label(xalign=0)
            desc.set_xalign(0)
            desc.set_width_chars(24)
            desc.set_max_width_chars(40)
            desc.set_wrap(True)
            desc.set_markup(f"<span size='11000' font_family='Inter' "
                            f"color='{pc_muted()}'>"
                            f"{escape(_digest_description(path))}</span>")
            words.append(desc)
            row.append(words)
            read = Gtk.Button(label="Read")
            read.add_css_class("gw-mini")
            read.set_valign(Gtk.Align.CENTER)
            read.connect("clicked", self._on_read_digest, path)
            row.append(read)
            inner.append(row)
        return self._settings_section(card)

    def _on_read_digest(self, _btn, path) -> None:
        """The in-app reader: the file's own words in one TextView, its
        own scroller inside the window's shell. Its size is a share of
        the window's own (never a fixed count), the same law GW-178
        keeps for every surface here."""
        path = pathlib.Path(path)
        dlg = Gtk.Window(title=f"Digest - {path.stem}")
        dlg.set_transient_for(self)
        w = self.get_allocated_width() or metrics.window_size()[0]
        h = self.get_allocated_height() or metrics.window_size()[1]
        dlg.set_default_size(int(w * 0.42), int(h * 0.6))
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        outer.set_margin_top(12); outer.set_margin_bottom(12)
        outer.set_margin_start(12); outer.set_margin_end(12)
        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scroller.set_vexpand(True)
        view = Gtk.TextView()
        view.set_wrap_mode(Gtk.WrapMode.WORD)
        view.set_left_margin(10); view.set_right_margin(10)
        view.set_editable(False)
        view.set_cursor_visible(False)
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            text = f"{path.name} could not be read."
        view.get_buffer().set_text(text)
        scroller.set_child(view)
        outer.append(scroller)
        dlg.set_child(outer)
        self._digest_viewer = dlg
        dlg.connect("destroy", self._digest_viewer_gone)
        dlg.present()

    def _digest_viewer_gone(self, *_a) -> None:
        self._digest_viewer = None
        return False

    def _help_start(self):
        """Where each page is and what it is for, in one glance - with the
        walkthrough's headline card first (he1)."""
        tour_card, tour_inner = self._settings_card(
            "Show me around",
            "Walks every page in rail order, one at a time, and points at "
            "each page's own controls. Stop ends it at any time.")
        start = Gtk.Button(label="Start the tour")
        start.add_css_class("gw-primary")
        start.set_valign(Gtk.Align.CENTER)
        start.set_halign(Gtk.Align.START)
        start.set_size_request(-1, 40)
        start.set_tooltip_text("One page every 1.2 s, skippable at any "
                               "time from the header.")
        start.connect("clicked", lambda *_a: (self._tour_start(),
                                              self._tour_step()))
        tour_inner.append(start)
        guide = Gtk.Grid()
        guide.set_column_spacing(22)
        guide.set_row_spacing(8)
        for row, (name, what) in enumerate((
                ("Wizard", "Guided setup, one task at a time."),
                ("Home", "The assistant, plus what just happened."),
                ("Protections", "One row per protection, every state."),
                ("Scans", "Every scan: buttons, progress, and the log."),
                ("Tools", "The whole tool table, with live status."),
                ("Browser Watch", "The hunter's findings and what they mean."),
                ("Endpoint Hardening", "Baseline checks, apply, verify, undo."),
                ("Logs", "The raw record, newest first."),
                ("Settings", "Theme, assistant, trusted items, updates."),
                ("Help", "What each protection does, in plain words."))):
            left = Gtk.Label(xalign=0)
            left.set_xalign(0)
            left.set_markup(f"<span size='13500' font_family='Inter' "
                            f"weight='600'>{escape(name)}</span>")
            right = Gtk.Label(xalign=0)
            right.set_xalign(0)
            right.set_wrap(True)
            # A minimum width, so the wrapped minimum HEIGHT is measured at
            # a readable width and not one word per line (see the Questions
            # pane: without it the page's minimum height doubles).
            right.set_width_chars(24)
            right.set_markup(f"<span size='13000' font_family='Inter' "
                             f"color='{pc_muted()}'>{escape(what)}</span>")
            guide.attach(left, 0, row, 1, 1)
            guide.attach(right, 1, row, 1, 1)
        card, inner = self._settings_card(
            "How to use it",
            "Six places, one job each. Nothing here needs a command.")
        inner.append(guide)
        return self._settings_section(tour_card, card)

    def _help_tools(self):
        """One line per protection: what it is, in a sentence.

        Two columns, one line of copy each, is the only shape in which all
        seventeen entries fit the 720px floor with every sentence intact —
        two-line rows need 65px each, which is 828px of window. The copy in
        ui/plain.py is written to that line (see the note there). On a wide
        pane the grid becomes three columns, where there is room to spare.
        """
        from ui.plain import FRIENDLY
        card, inner = self._settings_card("What each protection does")
        grid = Gtk.Grid()
        grid.set_column_spacing(12)
        grid.set_row_spacing(2)
        grid.set_column_homogeneous(True)
        cells = []
        for name, (fname, what) in FRIENDLY.items():
            if name not in self.by_name:
                continue
            cell = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            cell.add_css_class("gw-help-row")
            ic = Gtk.Image.new_from_icon_name(tool_icon(name))
            ic.set_pixel_size(14)
            ic.set_valign(Gtk.Align.CENTER)
            cell.append(ic)
            words = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
            words.set_hexpand(True)
            title = Gtk.Label(xalign=0)
            title.set_xalign(0)
            title.set_ellipsize(Pango.EllipsizeMode.END)
            title.set_markup(f"<span size='12500' font_family='Inter' "
                             f"weight='600'>{escape(fname)}</span>")
            words.append(title)
            body = Gtk.Label(xalign=0)
            body.set_xalign(0)
            # One line per tool, and the copy in ui/plain.py is written to
            # fit it — seventeen entries at two lines each need 65px a row,
            # which is 828px of window, past the 720px floor. width-chars
            # raises the label's MINIMUM width so the pane's minimum height
            # is measured at a readable width, not at a single word.
            body.set_wrap(True)
            body.set_lines(1)
            body.set_width_chars(16)
            body.set_max_width_chars(46)
            body.set_ellipsize(Pango.EllipsizeMode.END)
            body.set_markup(f"<span size='11000' font_family='Inter' "
                            f"color='{pc_muted()}'>{escape(what)}</span>")
            words.append(body)
            cell.append(words)
            cell.set_tooltip_text(f"{fname} ({name}) - {what}")
            cells.append(cell)

        # Two columns is the shape the page is measured in, so its minimum
        # height is right from the first layout. The grid widens to three
        # only on a wide pane, keyed on the grid's own width: that width is
        # the size the parent gives it, which does not change with the
        # column count (the columns are homogeneous and hexpanding), so the
        # decision cannot feed back into itself.
        cols = {"n": 2}
        for i, cell in enumerate(cells):
            grid.attach(cell, i % 2, i // 2, 1, 1)

        def _flow(_widget, _clock):
            width = grid.get_width()
            if width <= 0:
                return True
            want = 3 if width >= 1000 else 2
            if want == cols["n"]:
                return True
            cols["n"] = want
            for cell in cells:
                if cell.get_parent() is grid:
                    grid.remove(cell)
            for i, cell in enumerate(cells):
                grid.attach(cell, i % want, i // want, 1, 1)
            return True

        grid.add_tick_callback(_flow)
        inner.append(grid)
        return self._settings_section(card)

    def _help_questions(self):
        """The ten questions users ask most, two columns of five."""
        faq_lines = [
            ("What does greywatch do?",
             "One dashboard for every protection already on this computer."),
            ("How do I run a scan?",
             "Scans: press a scan button; each scanner shows "
             "its own progress."),
            ("How do I pause a protection?",
             "Protections or the Tools table: press Pause on its row; "
             "Resume brings it back."),
            ("What does At risk mean?",
             "A protection that should be running is not. Not a detection."),
            ("A detection appeared - what now?",
             "Read the Recent line or Logs. Quarantine what you didn't cause."),
            ("How do I isolate my machine?",
             "No one-click panic. Keep the firewall on; unplug to disconnect."),
            ("How do I change the theme?",
             "Settings - Appearance - Dark or Light."),
            ("Why is my antivirus quiet?",
             "Its full scan runs daily. Quiet means nothing bad was found."),
            ("Is my disk encrypted - how do I check?",
             "Not checked today. Run lsblk in a terminal; LUKS shows crypto."),
            ("How do I undo a wizard change?",
             "Endpoint Hardening - Undo last change."),
        ]
        card, inner = self._settings_card(
            "Questions",
            "The ten things owners ask most, each answered in one sentence.")
        grid = Gtk.Grid()
        grid.set_column_spacing(24)
        grid.set_row_spacing(10)
        grid.set_column_homogeneous(True)
        for i, (q, a) in enumerate(faq_lines):
            row = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
            qlabel = Gtk.Label(xalign=0)
            qlabel.set_xalign(0)
            qlabel.set_wrap(True)
            # max-width-chars sets the label's MINIMUM width, so GTK measures
            # the wrapped minimum HEIGHT at a readable width. Without it the
            # minimum height is computed at one character per line and this
            # pane alone reported 1162px — enough to force the whole window
            # taller than its 720px minimum.
            qlabel.set_width_chars(30)
            qlabel.set_max_width_chars(34)
            qlabel.set_markup(f"<span size='12500' font_family='Inter' "
                              f"weight='600'>{escape(q)}</span>")
            alabel = Gtk.Label(xalign=0)
            alabel.set_xalign(0)
            alabel.set_wrap(True)
            alabel.set_width_chars(30)
            alabel.set_max_width_chars(40)
            alabel.set_markup(f"<span size='12000' font_family='Inter' "
                              f"color='{pc_muted()}'>{escape(a)}</span>")
            row.append(qlabel)
            row.append(alabel)
            grid.attach(row, i % 2, i // 2, 1, 1)
        inner.append(grid)
        return self._settings_section(card)

    def _help_terminal(self):
        card, inner = self._settings_card(
            "From a terminal",
            "Optional. Everything the window shows can be read from a shell.")
        cmds = (("greywatch status", "Every protection and its state."),
                ("greywatch events", "The newest log lines."),
                ("greywatch tail", "Follow the log as it grows."),
                ("greywatch decisions", "What the app firewall decided."),
                ("greywatch rules", "The rules currently enforced."))
        cmd_grid = Gtk.Grid()
        cmd_grid.set_column_spacing(20)
        cmd_grid.set_row_spacing(7)
        for r, (cmd, what) in enumerate(cmds):
            cl = Gtk.Label(xalign=0)
            cl.set_xalign(0)
            cl.set_markup(f"<span size='12500' font_family='monospace'>"
                          f"{escape(cmd)}</span>")
            wl = Gtk.Label(xalign=0)
            wl.set_xalign(0)
            wl.set_wrap(True)
            wl.set_markup(f"<span size='12500' font_family='Inter' "
                          f"color='{pc_muted()}'>{escape(what)}</span>")
            cmd_grid.attach(cl, 0, r, 1, 1)
            cmd_grid.attach(wl, 1, r, 1, 1)
        inner.append(cmd_grid)
        where = Gtk.Label(xalign=0)
        where.set_xalign(0)
        where.set_wrap(True)
        where.set_markup(
            f"<span size='11500' font_family='Inter' color='{pc_soft()}'>"
            "The root watch daemon is greywatch.service. Events live in "
            "data/events.jsonl, status in data/status.json. Every privileged "
            "change runs through a helper with a backup and rollback."
            "</span>")
        inner.append(where)
        return self._settings_section(card)

    def _help_about(self):
        """The suite itself: what it is, which version, where to reach it,
        and the suite's own facts (he1): the registered protections the
        registry knows and the assistant's brain state.

        The About page lives here, next to the protections
        it explains, not in a separate dialog.
        """
        card, inner = self._settings_card(
            "About GreyWatch",
            "Linux endpoint security, with a local assistant.")
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=14)
        mark = Gtk.Image()
        mark.set_pixel_size(48)          # a pixbuf on its own paints at 16px
        wolf = (pathlib.Path(__file__).resolve().parents[1] / "assets"
                / "logo" / "greywatch-icon-128.png")
        if wolf.exists():
            mark.set_from_file(str(wolf))
        row.append(mark)
        words = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=1)
        name = Gtk.Label(xalign=0)
        name.set_xalign(0)
        name.set_markup(f"<span size='13500' font_family='Inter' "
                        f"weight='700'>GreyWatch {escape(self._version())}"
                        "</span>")
        words.append(name)
        why = Gtk.Label(xalign=0)
        why.set_xalign(0)
        why.set_wrap(True)
        why.set_width_chars(24)          # measure minimum height at a width
        why.set_markup(
            f"<span size='12500' font_family='Inter' "
            f"color='{pc_muted()}'>GreyWatch's protections watch this machine, the "
            "event trail stays on this machine, and the assistant's "
            "answers are composed from your own logs by a model that "
            "runs on your own CPU.</span>")
        words.append(why)
        row.append(words)
        inner.append(row)
        # The suite's own status line (he1): the registry the tool table
        # renders, stated once in plain words.
        suite = Gtk.Label(xalign=0)
        suite.set_xalign(0)
        suite.set_wrap(True)
        n = len(getattr(self, "by_name", None) or {})
        suite.set_markup(f"<span size='12500' font_family='Inter' "
                         f"color='{pc_muted()}'>{n} protections on file "
                         "in this build's registry; every row renders "
                         "from this machine.</span>")
        suite.set_width_chars(24)
        inner.append(suite)
        brains = Gtk.Label(xalign=0)
        brains.set_xalign(0)
        brains.set_wrap(True)
        brains.set_width_chars(24)
        brains.set_markup(f"<span size='12500' font_family='Inter' "
                          f"color='{pc_muted()}'>Assistant brain: "
                          f"{escape(self._brain_line())}.</span>")
        inner.append(brains)
        for uri, label in (
                ("https://github.com/greyok00/greywatch",
                 "Source and releases - github.com/greyok00/greywatch"),
        ):
            link = Gtk.LinkButton(uri=uri)
            link.set_label(label)
            link.add_css_class("gw-quiet")
            link.set_halign(Gtk.Align.START)
            inner.append(link)
        return self._settings_section(card)
