"""Per-tool CONFIG WIZARDS as detail-page forms (owner 2026-10-23: "where
is the wizards?"). Each form: plain-English label, builder-validated,
apply through the pkexec helpers, PREVIEW before apply."""
import pathlib
import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk  # noqa: E402


def _entry(hint, default=""):
    e = Gtk.Entry()
    e.set_text(default)
    e.set_placeholder_text(hint)
    return e


def _friendly(e) -> str:
    """rules.ValidationError talks in field IDs ("from-ip invalid: ...").
    On screen the app says it in words (Pass 3, 2026-10-23). The raw text
    is never shown to the person."""
    msg = str(e)
    for ident, words in (("from-ip", "the computer address"),
                         ("logpath", "the log file path"),
                         ("pattern", "the failure pattern"),
                         ("kind", "what to watch"),
                         ("action", "the action"),
                         ("comment", "the note")):
        msg = msg.replace(ident, words)
    return msg.replace(" invalid:", " is not valid:")


def form_for(tool: str, result_box) -> Gtk.Widget | None:
    """The tool's config panel; result_box = Gtk.Label for outcomes.

    The CALLER places result_box (the detail page packs it under the form).
    It must not be added to the form here: packing one widget twice is a
    Gtk-CRITICAL and the label silently stays inside the form box
    (found 2026-10-23 while opening every tool's detail page)."""
    if tool == "appfw":
        return _appfw(result_box)
    if tool == "ufw":
        return _ufw(result_box)
    if tool == "fail2ban":
        return _fail2ban(result_box)
    if tool == "tetragon":
        return _tetragon(result_box)
    if tool == "yara-watch" or tool == "yara-tmp-scan":
        return _yara(result_box)
    if tool == "arpwatch":
        return _arpwatch(result_box)
    return None                      # viewer-only tools: no config form


def _row(label, widget):
    b = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
    l = Gtk.Label(label=label)
    l.set_xalign(0)
    l.set_size_request(170, -1)
    widget.set_hexpand(True)
    b.append(l)
    b.append(widget)
    return b


# ── UFW: block/allow an IP + port ───────────────────────────────────────
def _appfw(result):
    """The app-fw rule form (owner's main lane): preview then store — the
    rule lands in the grey-owned store instantly (no popups, no helpers)."""
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
    box.set_margin_top(10)
    kind = Gtk.ComboBoxText()
    for k, lbl in (("allow", "ALLOW a program forever"),
                   ("deny", "DENY a program forever"),
                   ("trust", "TRUST a site (auto-allow)"),
                   ("block", "BLOCK a site (auto-deny)")):
        kind.append(k, lbl)
    kind.set_active(0)
    value = _entry("program path (e.g. /usr/lib/chromium/chromium) "
                   "or site name (e.g. example.com)")
    box.append(_row("Decision:", kind))
    box.append(_row("Target:", value))
    preview_ = Gtk.Button(label="Preview the exact rule")
    apply_ = Gtk.Button(label="Apply (stored instantly, no popups)")
    apply_.add_css_class("gw-cta")

    def _spec():
        k = kind.get_active_id()
        return ({"kind": "program", "action": k, "value": value.get_text().strip()}
                if k in ("allow", "deny") else
                {"kind": "site",
                 "action": "allow" if k == "trust" else "deny",
                 "value": value.get_text().strip()})

    def on_preview(_b):
        from wiz.appfw_wizard import appfw_build
        from appfw.rules import ValidationError
        try:
            built = appfw_build(_spec())
        except ValidationError as e:
            result.set_text(f"Check the values: {_friendly(e)}")
            return
        result.set_text(f"Will store: {built['preview']}. Press Apply.")

    def on_apply(_b):
        from wiz.appfw_wizard import apply_spec
        from appfw.rules import ValidationError
        try:
            built = apply_spec(_spec())
        except ValidationError as e:
            result.set_text(f"Check the values: {_friendly(e)}")
            return
        result.set_text(f"Stored: {built['preview']}\n"
                        f"(active when the engine is on; verify with "
                        f"`greywatch rules appfw list`)")

    preview_.connect("clicked", on_preview)
    apply_.connect("clicked", on_apply)
    box.append(_row("Preview:", preview_))
    box.append(_row("Store:", apply_))
    return box


def _ufw(result):
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
    box.set_margin_top(10)
    action = Gtk.ComboBoxText()
    for a in ("block", "allow", "rate-limit"):
        action.append(a, a)
    action.set_active(0)
    ip = _entry("which computer, e.g. 192.168.77.50")
    port = _entry("any port number (optional)")
    box.append(_row("What should happen:", action))
    box.append(_row("Which computer (IP):", ip))
    box.append(_row("Port (optional):", port))
    apply_ = Gtk.Button(label="Preview + apply firewall rule")
    apply_.add_css_class("gw-cta")

    def on_apply(_b):
        from rules import ufw_build, ValidationError
        from wiz import common
        spec = {"action": {"block": "deny", "allow": "allow",
                           "rate-limit": "limit"}[action.get_active_id()],
                "direction": "in", "from": ip.get_text().strip(),
                "port": port.get_text().strip(), "proto": "tcp", "comment": "gw-gui"}
        try:
            cmd = ufw_build(spec)
        except ValidationError as e:
            result.set_text(f"Check the values: {_friendly(e)}")
            return
        result.set_text(f"Applying: ufw {' '.join(cmd[1:])}. "
                        f"Your password prompt may appear…")
        rc = common.run_helper("ufw-apply", cmd[1:])
        result.set_text(f"Firewall rc={rc}. See the results in the rows.")

    apply_.connect("clicked", on_apply)
    w = _row("Rule:", apply_)
    box.append(w)
    return box


# ── FAIL2BAN: one jail ──────────────────────────────────────────────────
def _fail2ban(result):
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
    box.set_margin_top(10)
    jail = _entry("jail name, e.g. sshd-egress")
    logpath = _entry("log file to watch, e.g. /var/log/fail2ban.log")
    pattern = _entry("what counts as a failure, e.g. Ban .*?")
    box.append(_row("Jail name:", jail))
    box.append(_row("Log to watch:", logpath))
    box.append(_row("Failure pattern:", pattern))
    apply_ = Gtk.Button(label="Apply jail (defaults: 1 h ban, 3 tries)")
    box.append(_row("Apply:", apply_))

    def on_apply(_b):
        from rules import fail2ban_jail, fail2ban_filter, ValidationError
        from wiz import common
        j, lp, pat = (jail.get_text().strip(), logpath.get_text().strip(),
                      pattern.get_text().strip())
        try:
            fail2ban_jail(j, 3600, 600, 3, lp, j)
            if pat:
                fail2ban_filter(pat)
        except ValidationError as e:
            result.set_text(f"Check the values: {_friendly(e)}")
            return
        rc = common.run_helper("f2b-write",
                               [j, lp, 3, 600, 3600, j, pat])
        result.set_text(f"Fail2ban rc={rc}. The jail is live after reload.")
    apply_.connect("clicked", on_apply)
    return box


# ── TETRAGON: one tracing policy ────────────────────────────────────────
def _tetragon(result):
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
    box.set_margin_top(10)
    name = _entry("policy name, e.g. exec-tracer")
    kind = Gtk.ComboBoxText()
    for k, t in (("exec", "Watch programs starting"),
                 ("file_write", "Watch file writes"),
                 ("connect", "Watch network connects")):
        kind.append(k, t)
    kind.set_active(0)
    act = Gtk.ComboBoxText()
    for a, t in (("log-only", "Log only (safe)"), ("block", "Block (enforce)")):
        act.append(a, t)
    act.set_active(0)
    box.append(_row("Policy name:", name))
    box.append(_row("Watch for:", kind))
    box.append(_row("Do what:", act))
    preview_b = Gtk.Button(label="Preview the policy file")

    def on_preview(_b):
        from rules import tetragon_policy, ValidationError
        try:
            lines = tetragon_policy(kind.get_active_id(),
                                    name.get_text().strip(), {},
                                    act.get_active_id())
        except ValidationError as e:
            result.set_text(f"Check the values: {_friendly(e)}")
            return
        result.set_text("File:\n" + "\n".join(lines[:6]) +
                        "\n… apply via the helper (pkexec).")
    preview_b.connect("clicked", on_preview)
    box.append(_row("Preview:", preview_b))
    return box


# ── YARA: a rule with a REAL compile gate ───────────────────────────────
def _yara(result):
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
    box.set_margin_top(10)
    rname = _entry("rule name, e.g. gw_test")
    cond = _entry("YARA condition, e.g. filesize < 100KB", "true")
    box.append(_row("Rule name:", rname))
    box.append(_row("Condition:", cond))
    check_b = Gtk.Button(label="Compile-check with the real yara")
    box.append(_row("Check:", check_b))

    def on_check(_b):
        from wiz.yara_wizard import compile_gate
        ok, err = compile_gate(f"rule {rname.get_text().strip()} "
                               f"{{ condition: {cond.get_text().strip()} }}")
        result.set_text("Compiles. Good rule." if ok
                        else f"yara says: {err}")
    check_b.connect("clicked", on_check)
    return box


def _default_iface() -> str:
    probe = pathlib.Path("/proc/net/route")
    try:
        for row in probe.read_text().splitlines()[1:]:
            f = row.split()
            if len(f) > 7 and f[1] == "00000000":
                return f[0]
    except OSError:
        pass
    return ""


# ── ARPWATCH: per-iface config ──────────────────────────────────────────
def _arpwatch(result):
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
    box.set_margin_top(10)
    iface = _entry("WiFi/eth name (default route is prefilled)",
               _default_iface())
    args = _entry("extra options", "-N -p")
    flt = _entry("pcap filter (optional)")
    box.append(_row("Interface:", iface))
    box.append(_row("Options:", args))
    box.append(_row("Capture filter:", flt))
    apply_ = Gtk.Button(label="Apply arpwatch config")
    box.append(_row("Apply:", apply_))

    def on_apply(_b):
        from wiz import common
        rc = common.run_helper("arpwrite", [iface.get_text().strip(),
                                            "arpwatch", args.get_text().strip(),
                                            flt.get_text().strip()])
        result.set_text(f"arpwatch rc={rc}. The unit "
                        f"arpwatch@{iface.get_text().strip()} is configured.")
    apply_.connect("clicked", on_apply)
    return box
