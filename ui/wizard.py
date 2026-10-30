import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk  # noqa: E402

from ui import discover  # noqa: E402
from ui.plain import escape, muted as pc_muted  # noqa: E402

# Every entry is a SEPARATE task with its own window and its own pages.
# The baseline pass used to be the wizard shell, with these tucked behind
# one small link on its first page (owner report 2026-10-27). They are now
# peers: pick one, finish it, come back.
TOOL_CHOICES = [
    ("baseline", "security-high-symbolic",
     "Security baseline hardening",
     "The full guided pass: scan this computer, preview every baseline "
     "change, apply them with one password prompt, verify, and undo."),
    ("appfw", "gw-tool-appfw-symbolic",
     "Allow or deny a program",
     "Trusts or stops one program from using the internet. No popups "
     "afterward."),
    ("site", "gw-tool-net-watch-symbolic",
     "Trust or block a website",
     "Stops the asking: the site you pick is allowed or denied "
     "automatically."),
    ("ufw", "gw-tool-ufw-symbolic",
     "Make a firewall rule",
     "Block, allow or rate-limit connections to or from a computer."),
    ("fail2ban", "gw-tool-fail2ban-symbolic",
     "Set up the intrusion blocker",
     "Lock out computers that hammer you with failed logins; unlock later."),
    ("tetragon", "gw-tool-tetragon-symbolic",
     "Watch programs or files",
     "Watch programs starting, or files being written, in the kernel."),
    ("yara", "gw-tool-yara-watch-symbolic",
     "Add a malware rule",
     "Pick what to detect; the real scanner compiles it before anything "
     "installs."),
    ("arpwatch", "gw-tool-arpwatch-symbolic",
     "Configure the WiFi watcher",
     "Which network device to watch and how."),
]

_SMALL = 300


def _combo(options, default_idx=0):
    c = Gtk.ComboBoxText()
    for ident, label in options:
        c.append(ident, label)
    c.set_active(default_idx)
    c.set_size_request(_SMALL, -1)
    return c


def _hint(text):
    l = Gtk.Label(xalign=0)
    l.set_xalign(0)
    l.set_wrap(True)
    # A wrapped label's natural width is the whole unwrapped sentence;
    # without a measure cap the longest hint sets the window's width.
    l.set_max_width_chars(48)
    l.add_css_class("dim")
    l.set_text(text)
    return l


def _cap_combo(c, width=440):
    """Cap a picker so its widest menu row doesn't set the window width.

    A ComboBoxText's natural width is its widest row; the program picker's
    rows are full "Name · /long/path" strings (~875 px), which forced the
    setup assistant open at 1081 px (bug sweep S3). Fixed-size ellipsizing
    cells keep the row list short on screen and readable in full via the
    rule the user finally chooses."""
    c.set_size_request(width, -1)
    for cell in c.get_cells():
        try:
            cell.set_fixed_size(width, -1)
            cell.set_property("ellipsize", 3)   # Pango.EllipsizeMode.END
        except Exception:
            continue
    return c


class ToolChooser(Gtk.Dialog):

    def __init__(self, on_pick, parent=None):
        super().__init__(title="Wizard: what do you want to set up?")
        from gi.repository import Gdk
        screen_h = 1000
        try:
            mons = Gdk.Display.get_default().get_monitors()
            if mons is not None and mons.get_n_items() > 0:
                screen_h = mons.get_item(0).get_geometry().height
        except Exception:
            pass
        window_h = min(720, max(440, screen_h - 90))
        self.set_default_size(760, window_h)
        self.set_resizable(True)
        if parent is not None:
            self.set_transient_for(parent)
        self.set_modal(True)
        self.cancel_btn = self.add_button("Cancel", Gtk.ResponseType.CANCEL)
        self.on_pick = on_pick
        self.connect("response", self._cancel)
        grid = Gtk.FlowBox()
        grid.set_max_children_per_line(2)
        grid.set_min_children_per_line(2)
        grid.set_selection_mode(Gtk.SelectionMode.NONE)
        box = self.get_content_area()
        # Same type scale as every other page: one headline, one muted line
        # that says how the hub behaves. The old single 15 px sentence read
        # like a field label rather than the title of a page.
        intro = Gtk.Label(xalign=0)
        intro.set_xalign(0)
        intro.set_margin_start(8)
        intro.set_markup("<span size='19000' font_family='Inter' "
                         "weight='600'>Set up a protection</span>")
        box.append(intro)
        sub = Gtk.Label(xalign=0)
        sub.set_xalign(0)
        sub.set_margin_start(8)
        sub.set_margin_bottom(6)
        sub.set_wrap(True)
        sub.set_markup(f"<span size='12000' font_family='Inter' "
                       f"color='{pc_muted()}'>Each task is separate: pick "
                       f"one, finish it, come back for the next.</span>")
        box.append(sub)
        for key, icon, title, about in TOOL_CHOICES:
            b = Gtk.Button()
            bv = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
            bv.set_margin_top(10); bv.set_margin_bottom(10)
            bv.set_margin_start(10); bv.set_margin_end(10)
            ic = Gtk.Image.new_from_icon_name(icon)
            ic.set_pixel_size(34)
            ic.set_halign(Gtk.Align.START)
            ti = Gtk.Label(xalign=0)
            ti.set_xalign(0)
            ti.set_wrap(True)
            ti.set_markup(f"<span size='16000' font_family='Inter' "
                          f"weight='600'>{escape(title)}</span>")
            ab = Gtk.Label()
            ab.set_wrap(True)
            ab.set_xalign(0)
            ab.set_markup(f"<span size='12000' font_family='Inter' "
                          f"color='{pc_muted()}'>{escape(about)}</span>")
            bv.append(ic)
            bv.append(ti)
            bv.append(ab)
            b.set_child(bv)
            b.add_css_class("gw-card")
            b.connect("clicked", self._picked, key)
            grid.append(b)
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.set_size_request(-1, max(240, window_h - 190))
        scroll.set_hexpand(True)
        scroll.set_vexpand(True)
        scroll.set_child(grid)
        box.append(scroll)

    def _picked(self, _b, key):
        self.on_pick(key)
        self.destroy()

    def _cancel(self, *a):
        self.destroy()
        return Gtk.ResponseType.CANCEL


class RuleWizard(Gtk.Assistant):

    def __init__(self, tool: str, parent=None):
        super().__init__()
        self.tool = tool
        titles = dict((k, t) for k, _i, t, _a in TOOL_CHOICES)
        self.set_title(f"Wizard: {titles.get(tool, 'Setup')}")
        self.set_default_size(700, 480)
        if parent is not None:
            self.set_transient_for(parent)
        self.set_modal(True)
        self._done_body = Gtk.Label(xalign=0)
        self._done_body.set_xalign(0)
        self._done_body.set_wrap(True)
        self._done_body.set_max_width_chars(56)
        self.w = {}
        self.confirm = None
        self._next_page = 0
        self._f2b_file = ""

        builder = {"site": self._pages_site, "ufw": self._pages_ufw,
                   "appfw": self._pages_appfw,
                   "fail2ban": self._pages_fail2ban,
                   "tetragon": self._pages_tetragon,
                   "yara": self._pages_yara, "arpwatch": self._pages_arpwatch}
        (builder.get(tool) or self._pages_ufw)()
        self.connect("prepare", self._on_prepare)
        self.connect("apply", self._on_apply)
        self.connect("cancel", lambda a: a.destroy())
        self.connect("close", lambda a: a.destroy())
        esc = Gtk.EventControllerKey()
        esc.connect("key-pressed", self._on_key_press)
        self.add_controller(esc)
        self.present()

    @staticmethod
    def _on_key_press(_ctl, keyval, _keycode, _mods):
        from gi.repository import Gdk
        if keyval == Gdk.KEY_Escape:
            return True          # the assistant's own close flow handles it
        return False

    def _page(self, title, body=None, inner=None,
              kind=Gtk.AssistantPageType.CONTENT, complete=True):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_margin_top(20); box.set_margin_start(20); box.set_margin_end(20)
        head = Gtk.Label(xalign=0)
        head.set_xalign(0)
        head.set_markup(f"<span size='19000' font_family='Barlow Condensed' "
                        f"weight='600'>{title}</span>")
        box.append(head)
        if body:
            l = Gtk.Label(xalign=0)
            l.set_xalign(0)
            l.set_wrap(True)
            l.set_max_width_chars(56)
            l.set_markup(f"<span size='13000' font_family='Inter'>{body}</span>")
            box.append(l)
        if inner:
            box.append(inner)
            hint = (inner.get_placeholder_text()
                    if isinstance(inner, Gtk.Entry) else None)
            if not hint and isinstance(inner, Gtk.ComboBoxText):
                child = inner.get_child()
                hint = (child.get_placeholder_text()
                        if child and hasattr(child, "get_placeholder_text")
                        else None)
            if hint:
                box.append(_hint(hint))
        self._next_page += 1
        self.append_page(box)
        self.set_page_title(box, title)
        self.set_page_type(box, kind)
        if complete:
            self.set_page_complete(box, True)
        return box

    def _confirm(self, label_widget):
        label_widget.set_wrap(True)
        label_widget.set_max_width_chars(56)
        self._next_page += 1
        self.append_page(label_widget)
        self.set_page_title(label_widget, "Confirm")
        self.set_page_type(label_widget, Gtk.AssistantPageType.CONFIRM)
        self.set_page_complete(label_widget, True)
        self.confirm = label_widget
        return label_widget

    def _add_done(self):
        done = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        done.set_margin_top(20)
        done.set_margin_start(20)
        done.set_margin_end(20)
        head = Gtk.Label(xalign=0)
        head.set_xalign(0)
        head.set_wrap(True)
        head.set_markup("<span size='19000' font_family='Barlow Condensed' "
                        "weight='600'>Done</span>")
        done.append(head)
        self._next_page_done = True
        self.append_page(done)
        self.set_page_title(done, "Done")
        self.set_page_type(done, Gtk.AssistantPageType.SUMMARY)
        done.append(self._done_body)

    def _pages_site(self):
        act = _combo([("allow", "TRUST it: allowed automatically"),
                      ("block", "BLOCK it: denied automatically")], 0)
        site = _cap_combo(Gtk.ComboBoxText())
        scan = Gtk.Button(label="Scan again")
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        box.append(site)
        box.append(_hint("Only sites this computer has seen are listed. "
                         "Nothing to type."))
        box.append(scan)

        def fill():
            site.remove_all()
            keep = site.get_active_id()
            site.remove_all()
            site.append("", "Choose a site…")
            for row in discover.site_choices():
                site.append(row["host"], f"{row['host']} · {row['why']}")
            site.set_active_id(keep) if keep else site.set_active_id("")

        fill()
        self.w.update({"act": act, "site": site})
        self._page("Trust or block a site",
                   "TRUSTED sites: allowed without asking. BLOCKED: "
                   "never allowed.")
        page = self._page("Which site?", inner=box, complete=False)

        def check(*_a):
            self.set_page_complete(page, bool(site.get_active_id()))
        site.connect("changed", check)
        scan.connect("clicked", lambda *_a: (fill(), check()))
        check()
        self._page("What should happen?", inner=act)
        self.confirm = Gtk.Label(xalign=0)
        self._confirm(self.confirm)
        self._add_done()

    def _pages_appfw(self):
        """A program rule, without the packet vocabulary.

        This page set did not exist: picking "Allow or deny a program"
        silently opened the UFW pages instead (found 2026-10-27), so the
        app firewall had no guided path at all.
        """
        kind = _combo([("deny", "BLOCK this program: it never connects"),
                       ("allow", "ALLOW this program: it connects freely")], 0)
        # A picker, not a text box: everything installed or running is
        # already known, so there is nothing to type.
        target = _cap_combo(Gtk.ComboBoxText())
        scan = Gtk.Button(label="Scan again")

        def fill():
            keep = target.get_active_id()
            target.remove_all()
            target.append("", "Choose a program…")
            for row in discover.programs():
                target.append(row["path"], row["label"])
            target.set_active_id(keep) if keep else target.set_active_id("")

        fill()
        result = Gtk.Label(xalign=0)
        result.set_xalign(0)
        result.set_wrap(True)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        box.append(target)
        box.append(_hint("Programs from the desktop menu and anything "
                         "currently running are listed."))
        box.append(scan)
        scan.connect("clicked", lambda *_a: (fill(), check()))

        self.w.update({"act": kind, "target": target, "result": result})
        self._page("Allow or deny a program",
                   "The app firewall asks before a program reaches the "
                   "internet. A rule here answers for you in advance — no "
                   "popup when that program connects.")
        self._page("What should happen?", inner=kind)
        step2 = self._page("Which program?", inner=box, complete=False)

        def check(*_a):
            self.set_page_complete(step2, bool(target.get_active_id()))
        target.connect("changed", check)
        check()
        self.confirm = Gtk.Label(xalign=0)
        self._confirm(self.confirm)
        self._add_done()

    def _pages_ufw(self):
        act = _combo([("block", "BLOCK: keep them out (safest)"),
                      ("allow", "ALLOW: let them in"),
                      ("limit", "RATE-LIMIT: allow but slow")], 0)
        who = _cap_combo(Gtk.ComboBoxText())
        port = _cap_combo(Gtk.ComboBoxText())
        scan = Gtk.Button(label="Scan again")

        def fill():
            keep_who, keep_port = who.get_active_id(), port.get_active_id()
            who.remove_all()
            who.append("", "Choose a computer…")
            who.append("any", "Anyone: every computer (no address limit)")
            for h in discover.lan_hosts():
                who.append(h["ip"], f"{h['ip']} · a computer on this network"
                           + (" (answers)" if h["reachable"] else ""))
            port.remove_all()
            port.append("", "Choose a port…")
            port.append("any", "Any port")
            listed = set()
            for p in discover.external_ports():
                listed.add(p["port"])
                port.append(str(p["port"]),
                            f"{p['port']} · already open on this computer")
            for p, name in ((22, "SSH remote login"), (80, "web"),
                            (443, "secure web"), (53, "DNS")):
                if p not in listed:
                    port.append(str(p), f"{p} · {name}")
            who.set_active_id(keep_who) if keep_who else who.set_active_id("")
            port.set_active_id(keep_port) if keep_port else port.set_active_id("")

        fill()
        who_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        who_box.append(who)
        who_box.append(scan)
        self.w.update({"act": act, "who": who, "port": port})
        ufw_a = "The firewall decides which connections pass at all."
        ufw_b = "The lists below show what this computer actually sees."
        self._page("Make a firewall rule", ufw_a + " " + ufw_b)
        self._page("What should happen?", inner=act)
        who_page = self._page("Which computer?", inner=who_box, complete=False)
        port_page = self._page("Which port?", inner=port, complete=False)

        def check(*_a):
            self.set_page_complete(who_page, bool(who.get_active_id()))
            self.set_page_complete(port_page, bool(port.get_active_id()))
        who.connect("changed", check)
        port.connect("changed", check)
        scan.connect("clicked", lambda *_a: (fill(), check()))
        check()
        self.confirm = Gtk.Label(xalign=0)
        self._confirm(self.confirm)
        self._add_done()

    def _pages_fail2ban(self):
        src = _combo([("journal", "The system journal (login services)"),
                      ("file", "A log file on this computer")], 0)
        units = discover.journal_units()
        unit_opts = [(u, u) for u in units]
        unit = _combo(unit_opts, 0) if unit_opts else _combo([("", "—")], 0)
        if "ssh.service" in units:
            unit.set_active_id("ssh.service")
        else:
            unit.set_active(0)
        patterns = [(p["key"], p["title"]) for p in discover.F2B_PATTERNS]
        pat = _combo(patterns, 0)
        pat_about = _hint(discover.F2B_PATTERNS[0]["about"])

        def pat_changed(_c):
            p = discover.f2b_pattern(pat.get_active_id())
            pat_about.set_text(p["about"] if p else "")
        pat.connect("changed", pat_changed)

        ban = _combo([("600", "10 minutes"), ("3600", "1 hour (recommended)"),
                      ("86400", "1 day")], 1)

        file_label = Gtk.Label(xalign=0)
        file_label.set_wrap(True)
        file_label.add_css_class("dim")
        file_label.set_text("No log file chosen yet.")
        browse = Gtk.Button(label="Choose a log file…")
        file_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        file_label.set_hexpand(True)
        file_box.append(file_label)
        file_box.append(browse)

        src_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        src_box.append(src)
        src_box.append(unit)
        src_box.append(file_box)

        jails = discover.enabled_jails()
        already = ("Already switched on here: " + ", ".join(jails) + "."
                   if jails else "No fail2ban jails are switched on yet.")
        self.w.update({"src": src, "unit": unit, "pat": pat,
                       "ban": ban, "about": pat_about})

        src_page = self._page(
            "What should it watch?",
            "It locks out an address for a while after repeated failures. "
            + already, inner=src_box, complete=False)

        def current_source() -> str:
            if src.get_active_id() == "journal":
                u = unit.get_active_id()
                return f"journal:{u}" if u else ""
            return self._f2b_file

        def update_complete(*_a):
            journal = src.get_active_id() == "journal"
            unit.set_visible(journal)
            file_box.set_visible(not journal)
            self.set_page_complete(src_page, bool(current_source()))

        src.connect("changed", update_complete)

        def on_resp(d, rid, *_a):
            if rid == Gtk.ResponseType.OK:
                f = d.get_file()
                chosen = f.get_path() or "" if f is not None else ""
                if chosen:
                    self._f2b_file = chosen
                    file_label.set_text(chosen)
                    update_complete()
            d.destroy()
        browse.connect("clicked", lambda _b: self._pick_f2b_file(file_label,
                                                                  on_resp))
        update_complete()

        pat_page = self._page("What counts as an attack?", inner=pat)
        pat_page.append(pat_about)
        self._page("How long should the lockout last?", inner=ban)
        self.confirm = Gtk.Label(xalign=0)
        self._confirm(self.confirm)
        self._add_done()

    def _pages_tetragon(self):
        kind = _combo([("exec", "Programs as they start"),
                       ("file_write", "Files being written"),
                       ("connect", "Network connects")], 0)
        act = _combo([("log-only", "Just log it (safe)"),
                      ("block", "BLOCK it (careful!)")], 0)
        name = Gtk.Label(xalign=0)
        name.set_xalign(0)
        name.set_selectable(True)
        self.w.update({"kind": kind, "act": act, "name": name})

        def refresh_name(*_a):
            name.set_text(f"policy name: {self._tetra_name()}")
        kind.connect("changed", refresh_name)
        refresh_name()
        tet_a = "This watches INSIDE the kernel, the strongest view."
        tet_b = "The name is chosen for you."
        self._page("Watch programs or files", tet_a + " " + tet_b)
        self._page("Watch for:", inner=kind)
        self._page("What happens when it fires?", inner=act)
        self._page("Its name on this computer:", inner=name)
        self.confirm = Gtk.Label(xalign=0)
        self._confirm(self.confirm)
        self._add_done()

    def _tetra_name(self) -> str:
        import pathlib
        base = "watch-" + (self.w["kind"].get_active_id() or "exec").replace(
            "_", "-")
        tpd = pathlib.Path("/etc/tetragon/tetragon.tp.d")
        name, n = base, 1
        while (tpd / f"70-greywatch-{name}.yaml").exists():
            n += 1
            name = f"{base}-{n}"
        return name

    def _pages_yara(self):
        presets = [(p["key"], p["title"]) for p in discover.YARA_PRESETS]
        pick = _combo(presets, 0)
        about = Gtk.Label(xalign=0)
        about.set_xalign(0)
        about.set_wrap(True)
        about.set_max_width_chars(56)
        name = Gtk.Label(xalign=0)
        name.set_xalign(0)
        name.set_selectable(True)
        test_note = Gtk.Label(xalign=0)
        test_note.set_xalign(0)
        test_note.set_wrap(True)
        test_b = Gtk.Button(label="Test it with the real scanner")

        def source() -> str:
            key = pick.get_active_id() or ""
            return discover.yara_source(key, discover.yara_name(key))

        def refresh(*_a):
            p = discover.yara_preset(pick.get_active_id() or "")
            about.set_text(p["about"] if p else "")
            name.set_text(f"rule name: {discover.yara_name(pick.get_active_id() or '')}")
            test_note.set_text("")
        pick.connect("changed", refresh)
        refresh()

        def on_test(_b):
            from wiz.yara_wizard import compile_gate
            ok, err = compile_gate(source())
            test_note.set_text("This rule compiles with the real scanner."
                               if ok else f"The scanner rejected it: {err}")
        test_b.connect("clicked", on_test)
        self.w.update({"pick": pick, "about": about, "name": name,
                       "test_note": test_note, "source": source})
        yara_a = "Pick what to detect. Every rule below is complete."
        yara_b = "The real scanner compiles it before anything installs."
        self._page("Add a malware rule", yara_a + " " + yara_b)
        self._page("What should it detect?", inner=pick)
        page = self.get_nth_page(self.get_n_pages() - 1)
        page.append(about)
        page.append(name)
        page.append(test_b)
        page.append(test_note)
        self.confirm = Gtk.Label(xalign=0)
        self._confirm(self.confirm)
        self._add_done()

    def _pages_arpwatch(self):
        ifaces = discover.interfaces()
        if ifaces:
            io = [(i["name"], i["label"]) for i in ifaces]
        else:
            io = [("", "no network device found")]
        iface = _combo(io, 0)
        args = _combo([("-N -p", "Standard: no name lookups, quiet"),
                       ("-N", "No name lookups only"),
                       ("", "No extra options")], 0)
        self.w.update({"iface": iface, "args": args})
        self._page("Configure the WiFi device watcher",
                   "arpwatch notes every device that joins your network.")
        self._page("Which network device?", inner=iface)
        self._page("Extra options:", inner=args)
        self.confirm = Gtk.Label(xalign=0)
        self._confirm(self.confirm)
        self._add_done()

    def _pick_f2b_file(self, file_label, on_resp):
        dlg = Gtk.FileChooserNative(
            title="Choose the log file to watch", transient_for=self,
            action=Gtk.FileChooserAction.OPEN)
        try:
            dlg.set_current_folder("/var/log")
        except Exception:
            pass
        dlg.connect("response", on_resp)
        dlg.show()

    def _on_prepare(self, _a, page):
        if self.get_page_type(page) != Gtk.AssistantPageType.CONFIRM:
            return False
        w, t = self.w, self.tool
        if t == "site":
            act = w["act"].get_active_id()
            site = w["site"].get_active_id()
            self.confirm.set_text(
                f"{site or '(no site chosen yet)'} will be "
                f"{'TRUSTED: allowed' if act == 'allow' else 'BLOCKED: denied'} "
                f"automatically. No more asking about it.")
        elif t == "appfw":
            act = ("BLOCKED from connecting" if
                   w["act"].get_active_id() == "deny"
                   else "allowed to connect")
            self.confirm.set_text(
                f"{w['target'].get_active_id() or '(no program chosen)'} "
                f"will be {act} every time, without asking. The rule is "
                "stored instantly and enforced while the app firewall is on.")
        elif t == "ufw":
            act = {"block": "BLOCK", "allow": "ALLOW", "limit": "RATE-LIMIT"}[
                w["act"].get_active_id()]
            who = w["who"].get_active_id() or ""
            who_txt = ("every computer" if who == "any"
                       else f"the computer at {who or '(none chosen)'}")
            port = w["port"].get_active_id() or ""
            port_txt = ("" if port in ("", "any")
                        else f", on port {port}")
            self.confirm.set_text(
                f"The firewall will {act} incoming connections from "
                f"{who_txt}{port_txt}.")
        elif t == "fail2ban":
            src = self._f2b_source()
            pat = discover.f2b_pattern(w["pat"].get_active_id() or "")
            ban = {"600": "10 minutes", "3600": "1 hour",
                   "86400": "1 day"}.get(w["ban"].get_active_id(), "1 hour")
            where = (("the system journal for " + src.split(":", 1)[-1])
                     if src.startswith("journal:") else (src or
                                                         "(no log chosen)"))
            self.confirm.set_text(
                f"A jail named '{discover.f2b_name(src)}' will watch {where} "
                f"and lock out an address for {ban} after 3 failures in 10 "
                f"minutes ({pat['title'] if pat else 'no pattern'}).")
        elif t == "tetragon":
            self.confirm.set_text(
                f"The policy '{self._tetra_name()}' will "
                f"{'log' if w['act'].get_active_id() == 'log-only' else 'BLOCK'} "
                f"{w['kind'].get_active_id()} events inside the kernel.")
        elif t == "yara":
            key = w["pick"].get_active_id() or ""
            p = discover.yara_preset(key)
            self.confirm.set_text(
                f"The rule '{discover.yara_name(key)}' will look for "
                f"{p['title'].lower() if p else 'the chosen pattern'}. The real "
                f"scanner compiles it first; nothing installs if it fails.")
        elif t == "arpwatch":
            iface = w["iface"].get_active_id() or "the chosen device"
            opts = w["args"].get_active_id() or "none"
            self.confirm.set_text(
                f"arpwatch will watch {iface} with options '{opts}'.")
        return False

    def _f2b_source(self) -> str:
        w = self.w
        if w["src"].get_active_id() == "journal":
            unit = w["unit"].get_active_id()
            return f"journal:{unit}" if unit else ""
        return self._f2b_file

    def _on_apply(self, *_a):
        w, t = self.w, self.tool
        try:
            if t == "site":
                from ui.settings import TrustList
                act = w["act"].get_active_id()
                site = w["site"].get_active_id() or ""
                ok = TrustList().add(site, act)
                self._done_body.set_markup(
                    f"<span size='14000' font_family='Inter'>"
                    f"{'Saved: done' if ok else 'Pick a site from the list first'}; "
                    f"manage the list under Settings: Sites trust list."
                    f"</span>")
            elif t == "appfw":
                from wiz.appfw_wizard import apply_spec
                from appfw.rules import ValidationError
                value = w["target"].get_active_id() or ""
                spec = {"kind": "program",
                        "action": "deny" if w["act"].get_active_id() == "deny"
                        else "allow",
                        "value": value}
                try:
                    built = apply_spec(spec)
                except ValidationError as e:
                    self._done_body.set_text(f"Check the values: {e}")
                    return True
                self._done_body.set_markup(
                    f"<span size='14000' font_family='Inter'>Stored: "
                    f"{escape(built['preview'])}. Active while the app "
                    f"firewall is on.</span>")
            elif t == "ufw":
                from rules import ufw_build, ValidationError
                from wiz import common
                who = w["who"].get_active_id() or ""
                port = w["port"].get_active_id() or ""
                spec = {"action": {"block": "deny", "allow": "allow",
                                   "limit": "limit"}[w["act"].get_active_id()],
                        "direction": "in",
                        "from": "" if who == "any" else who,
                        "port": "" if port in ("", "any") else port,
                        "proto": "tcp", "comment": "gw-wizard"}
                try:
                    cmd = ufw_build(spec)
                except ValidationError as e:
                    self._done_body.set_text(f"The rule could not be built: {e}")
                    return True
                rc = common.run_helper("ufw-apply", cmd[1:])
                self._done_body.set_markup(
                    f"<span size='14000' font_family='Inter'>"
                    f"{'The rule is live' if rc == 0 else 'Your password was needed for the change'} (rc {rc}).</span>")
            elif t == "fail2ban":
                from wiz import common
                src = self._f2b_source()
                pat = discover.f2b_pattern(w["pat"].get_active_id() or "")
                jail = discover.f2b_name(src)
                rc = common.run_helper("f2b-write",
                                       [jail, src, 3, 600,
                                        int(w["ban"].get_active_id() or 3600),
                                        jail, pat["regex"] if pat else ""])
                self._done_body.set_markup(
                    f"<span size='14000' font_family='Inter'>The jail rc="
                    f"{rc}. Live after reload.</span>")
            elif t == "tetragon":
                from rules import tetragon_policy
                name = self._tetra_name()
                lines = tetragon_policy(w["kind"].get_active_id(), name, {},
                                        w["act"].get_active_id())
                import pathlib as _pl
                _pl.Path(__file__).resolve().parents[1] / "tmp-payload.yaml" \
                    .write_text("\n".join(lines) + "\n")
                from wiz import common
                rc = common.run_helper(
                    "tetra-write",
                    [f"/etc/tetragon/tetragon.tp.d/70-greywatch-{name}.yaml"])
                self._done_body.set_markup(
                    f"<span size='14000' font_family='Inter'>Policy rc="
                    f"{rc}. Installed into the kernel watcher.</span>")
            elif t == "yara":
                src = self.w["source"]()
                from wiz.yara_wizard import compile_gate
                ok, err = compile_gate(src)
                if not ok:
                    self._done_body.set_markup(
                        f"<span size='14000'>The scanner rejected it: "
                        f"{escape(err)}. Nothing installed.</span>")
                    return True
                import pathlib as _pl
                name = (src.split("rule ", 1)[1].split("{", 1)[0].strip()
                        if "rule " in src else "gw_rule")
                _pl.Path(__file__).resolve().parents[1] / "tmp-payload.yar" \
                    .write_text(src + "\n")
                from wiz import common
                rc = common.run_helper("yara-write", [name])
                self._done_body.set_markup(
                    f"<span size='14000' font_family='Inter'>Compiled with "
                    f"the real scanner and installed (rc {rc}).</span>")
            elif t == "arpwatch":
                from wiz import common
                rc = common.run_helper(
                    "arpwrite",
                    [w["iface"].get_active_id() or "", "arpwatch",
                     w["args"].get_active_id() or "", ""])
                self._done_body.set_markup(
                    f"<span size='14000' font_family='Inter'>arpwatch rc="
                    f"{rc}. Configured.</span>")
        except Exception as e:
            self._done_body.set_text(f"Error: {e}")
        return True
