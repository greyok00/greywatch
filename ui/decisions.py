import json
import os
import pathlib
import re
import threading
import time

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Notify", "0.7")
from gi.repository import Gtk, GLib, Notify as _NotifyModule  # noqa: E402

import greywatch_daemon as dm
from decisions_factory import pending_ids, record_answer


def _primary_index(opts):
    for i, o in enumerate(opts):
        if o.get("tone") == "primary":
            return i
    return 0


def _tone(o):
    tone = o.get("tone")
    if tone in ("primary", "danger", "quiet"):
        return tone
    oid = str(o.get("id", "")).lower()
    if any(w in oid for w in ("deny", "block", "restore", "unban", "lift")):
        return "danger"
    return "quiet"


_PORT_WORDS = {80: "web", 443: "secure web", 53: "name lookup",
               22: "remote login", 25: "mail", 993: "secure mail",
               5222: "chat", 3478: "calls", 5228: "push messages"}


def _spec_facts(spec):
    """Pull the program and destination out of a decision spec.

    New daemons send structured fields; older ask files only have a
    two-line ``detail`` string, and the dashboard must still be able to
    draw the identity card for those.
    """
    host = str(spec.get("host") or "")
    path = str(spec.get("path") or "")
    app = str(spec.get("app_name") or "")
    port = int(spec.get("port") or 0)
    proto = str(spec.get("proto") or "")
    detail = str(spec.get("detail") or "")
    if detail and (not path or not host or not port):
        first = detail.split("\n", 1)[0].strip()
        if not path and first.startswith("/") and len(first) < 240:
            path = first
        m = re.search(r"→\s*(\S+):(\d+)", detail)
        if m:
            host = host or m.group(1)
            port = port or int(m.group(2))
        if not proto:
            m2 = re.search(r"\((tcp6?|udp6?)\)", detail)
            proto = (m2.group(1) if m2 else "").replace("6", "")
    if not app and path:
        app = os.path.basename(path)
    return {"host": host, "path": path, "app_name": app,
            "port": port, "proto": proto}


def _address_line(facts) -> str:
    host = facts["host"] or "an unknown address"
    if not facts["port"]:
        return host
    word = _PORT_WORDS.get(facts["port"])
    tail = f" ({word})" if word else ""
    return f"{host} · port {facts['port']}{tail}"


def _identity_card(spec, dlg):
    """The "who is this?" card: program on top, destination below.

    Owner report 2026-10-28: a prompt reading ``57.144.134.145:443`` with
    an unknown app gave no way to decide. The answer is looked up in a
    worker thread (reverse DNS + whois + the local country table) so the
    buttons appear immediately and fill in a second later.
    """
    facts = _spec_facts(spec)
    if not (facts["host"] or facts["path"]):
        return None
    card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
    card.add_css_class("gw-idcard")

    top = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
    icon = Gtk.Image.new_from_icon_name("application-x-executable-symbolic")
    icon.set_pixel_size(28)
    icon.add_css_class("gw-idicon")
    text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
    text.set_hexpand(True)
    prog = Gtk.Label(label="Checking which program this is…", xalign=0,
                     wrap=True)
    prog.add_css_class("gw-idname")
    prog_line = Gtk.Label(label="", xalign=0, wrap=True)
    prog_line.add_css_class("gw-idline")
    prog_line.set_visible(False)
    text.append(prog)
    text.append(prog_line)
    top.append(icon)
    top.append(text)
    card.append(top)
    card.append(Gtk.Separator())

    dest_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
    # A drawn country tile instead of a flag emoji: emoji ignore the theme
    # and render differently on every machine, and there is no flag icon
    # set installed. It shows the two-letter code until the lookup answers.
    flag = Gtk.Label(label="··", xalign=0.5, yalign=0.5)
    flag.add_css_class("gw-idflag")
    flag.set_size_request(54, 40)
    dest_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
    dest_box.set_hexpand(True)
    dest = Gtk.Label(label="Looking up this address…", xalign=0, wrap=True)
    dest.add_css_class("gw-idname")
    dest_line = Gtk.Label(label=_address_line(facts), xalign=0, wrap=True,
                          selectable=True)
    dest_line.add_css_class("gw-idval")
    dest_sentence = Gtk.Label(label="", xalign=0, wrap=True)
    dest_sentence.add_css_class("gw-idline")
    dest_sentence.set_visible(False)
    dest_box.append(dest)
    dest_box.append(dest_line)
    dest_box.append(dest_sentence)
    dest_row.append(flag)
    dest_row.append(dest_box)
    card.append(dest_row)
    grid = Gtk.Grid(column_spacing=18, row_spacing=6)
    grid.set_margin_top(4)
    card.append(grid)
    warn = Gtk.Label(label="", xalign=0, wrap=True)
    warn.add_css_class("gw-idwarn")
    warn.set_visible(False)
    card.append(warn)

    state = {"alive": True}

    def _set_icon(name):
        try:
            theme = Gtk.IconTheme.get_for_display(icon.get_display())
            if name and theme.has_icon(name):
                icon.set_from_icon_name(name)
                return
        except Exception:
            pass
        icon.set_from_icon_name("application-x-executable-symbolic")

    def fill(result):
        if not state["alive"]:
            return False
        result = result if isinstance(result, dict) else {}
        p = result.get("program_card") or {}
        h = result.get("host_card") or {}
        prog.set_text(p.get("title") or facts["app_name"] or "Unknown program")
        prog_line.set_text(p.get("sentence") or "")
        prog_line.set_visible(bool(p.get("sentence")))
        dest.set_text(h.get("title") or "Unknown server")
        dest_sentence.set_text(h.get("sentence") or "")
        dest_sentence.set_visible(bool(h.get("sentence")))
        code = str((result.get("host") or {}).get("country") or "")
        flag.set_text(code[:2].upper() or "··")
        while (child := grid.get_first_child()) is not None:
            grid.remove(child)
        for i, (key, val) in enumerate(h.get("rows") or []):
            k = Gtk.Label(label=str(key), xalign=0)
            k.add_css_class("gw-idkey")
            v = Gtk.Label(label=str(val), xalign=0, wrap=True, selectable=True)
            v.add_css_class("gw-idval")
            grid.attach(k, 0, i, 1, 1)
            grid.attach(v, 1, i, 1, 1)
        msg = " ".join(x for x in (p.get("warning"), h.get("warning")) if x)
        warn.set_text(msg)
        warn.set_visible(bool(msg))
        _set_icon(p.get("icon"))
        return False

    def worker():
        try:
            from ui import identity
            result = identity.describe_connection(
                facts["host"], facts["path"], facts["app_name"])
        except Exception:
            result = {}
        GLib.idle_add(fill, result)

    dlg.connect("destroy", lambda *_a: state.__setitem__("alive", False))
    threading.Thread(target=worker, daemon=True).start()
    return card


def _decision_dialog(spec, modal=False, eyebrow="Protection", on_learn=None):
    """One subject per window, OpenSnitch style: what it is, then two answers.

    The question used to live only in the title bar, which this desktop does
    not draw, so every popup looked like a nameless allow/deny box (owner
    report 2026-10-27). Everything that matters is now in the body, in one
    glance: a small category label, the subject in plain words, and the raw
    detail underneath.
    """
    opts = spec.get("options", [])
    dlg = Gtk.Dialog(title="Greywatch", modal=modal)
    dlg.set_default_size(560, -1)
    dlg.add_css_class("gw-popup")
    area = dlg.get_content_area()

    head = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
    head.add_css_class("gw-popup-header")
    cat = Gtk.Label(label=(spec.get("eyebrow") or eyebrow).upper(),
                    xalign=0)
    cat.add_css_class("gw-eyebrow")
    subject = spec.get("subject") or spec["question"].split("\n", 1)[0]
    title = Gtk.Label(label=subject, xalign=0, wrap=True,
                      selectable=True)
    title.add_css_class("gw-headline")
    head.append(cat)
    head.append(title)
    detail = spec.get("detail")
    if detail:
        meta = Gtk.Label(label=detail, xalign=0, wrap=True,
                         selectable=True)
        meta.add_css_class("gw-meta")
        head.append(meta)
    area.append(head)

    card = _identity_card(spec, dlg)
    if card is not None:
        area.append(card)

    if spec.get("question") and spec.get("detail"):
        body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        body.add_css_class("gw-popup-body")
        q = Gtk.Label(label=spec["question"], xalign=0, wrap=True,
                      selectable=True)
        q.add_css_class("gw-meta")
        body.append(q)
        area.append(body)

    actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
    actions.add_css_class("gw-popup-actions")
    actions.set_halign(Gtk.Align.FILL)
    # Six answers (block/allow once, always, and the two site rules) do
    # not fit on one 560 px line; a flow box wraps them instead of
    # clipping the last button.
    buttons = Gtk.FlowBox()
    buttons.set_selection_mode(Gtk.SelectionMode.NONE)
    buttons.set_halign(Gtk.Align.END)
    buttons.set_hexpand(True)
    buttons.set_max_children_per_line(3)
    buttons.set_min_children_per_line(1)
    buttons.set_column_spacing(8)
    buttons.set_row_spacing(8)
    buttons.set_homogeneous(False)
    actions.append(buttons)
    first = None
    for i, o in enumerate(opts):
        b = Gtk.Button(label=o["label"])
        b.add_css_class("gw-" + _tone(o))
        b.connect("clicked", lambda _b, idx=i: dlg.response(idx))
        buttons.append(b)
        if i == _primary_index(opts):
            first = b
    area.append(actions)

    # A flood of prompts is the one thing this firewall cannot ask about:
    # the operator needs one click that stops the asking and keeps
    # recording (owner report 2026-10-28). Learning mode already existed,
    # but only inside Settings, which is not where you are when twenty
    # boxes are stacked up.
    if on_learn is not None and str(spec.get("id", "")).startswith("appfw:"):
        learn = Gtk.Button(label="Stop asking for 15 minutes "
                                 "(learning mode)")
        learn.add_css_class("gw-quiet")
        learn.add_css_class("gw-learn")
        learn.set_halign(Gtk.Align.START)
        learn_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL,
                            spacing=8)
        learn_row.add_css_class("gw-popup-learn")
        learn_row.append(learn)

        def _learn(_b):
            allow_idx = next((i for i, o in enumerate(opts)
                              if o.get("id") == "allow-once"), None)
            try:
                on_learn(15)
            except Exception:
                pass
            dlg.response(allow_idx if allow_idx is not None else 0)
        learn.connect("clicked", _learn)
        area.append(learn_row)

    if first is not None:
        dlg.set_default_widget(first)

        def _grab(*_a):
            first.grab_focus()
            return False
        dlg.connect("map", lambda *_a: GLib.idle_add(_grab))

    # Esc answers nothing (the decision stays pending) and closes the box.
    key = Gtk.EventControllerKey()
    key.connect("key-pressed", _on_escape, dlg)
    dlg.add_controller(key)
    return dlg


def _on_escape(_c, keyval, _code, _state, dlg):
    from gi.repository import Gdk
    if keyval == Gdk.KEY_Escape:
        dlg.response(Gtk.ResponseType.DELETE_EVENT)
        return True
    return False


class DecisionBroker:

    STALE_AFTER = 900.0          # unanswered prompts older than this are noise
    # OpenSnitch applies the previous answer to an identical connection
    # repeated within 2 s instead of prompting again (opensnitch-zenity
    # README, captured by greysearch 2026-10-27). Without this, one app
    # opening a dozen parallel sockets queued a dozen identical popups.
    ASK_MEMO_SECONDS = 2.0

    def __init__(self):
        self._shown = set()          # one dialog per spec id, per session
        self._tray = None
        self._active = None          # only ONE popup on screen at a time
        self._queue = []             # pending popups, served FIFO
        self._last_events = []
        self._recent = {}            # (subject, host) -> (expiry, answer)
        self._recent_lock = threading.Lock()

    def set_tray(self, tray):
        self._tray = tray

    @staticmethod
    def _fresh(ts, now=None) -> bool:
        """A backlog of unanswered prompts from hours ago must not open a
        stack of dialogs the moment the GUI starts (owner report: 5+ windows
        at once). Only recent asks are worth interrupting for; older ones
        stay visible in the dashboard."""
        import datetime as _dt
        if not ts:
            return True
        try:
            when = _dt.datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        except ValueError:
            return True
        if when.tzinfo is None:
            when = when.replace(tzinfo=_dt.timezone.utc)
        now = now or _dt.datetime.now(_dt.timezone.utc)
        return (now - when).total_seconds() <= DecisionBroker.STALE_AFTER

    def pump(self, events) -> int:
        self._last_events = list(events or [])
        try:
            answered = pending_ids(dm.DATA_DIR / "decisions.jsonl")
        except OSError:
            answered = set()
        fresh = []
        for e in reversed(events):
            if not isinstance(e, dict):
                continue
            spec = e.get("interaction")
            if not spec:
                continue
            sid = spec["id"]
            if sid in answered or sid in self._shown:
                continue
            if sid.startswith("appfw:"):      # raised by the ask path below
                continue
            if not self._fresh(e.get("ts")):
                self._shown.add(sid)          # never queue it later either
                continue
            self._shown.add(sid)
            fresh.append({"spec": spec, "eyebrow": "Protection"})
        self._queue.extend(fresh)
        opened = self._serve_next()
        try:
            self._notify_denies(events)
        except Exception:
            pass
        try:
            self._notify_critical(events)
        except Exception:
            pass
        return opened

    def _serve_next(self) -> int:
        if self._active is not None or not self._queue:
            return 0
        item = self._queue.pop(0)
        self._active = item["spec"]["id"]
        self._show_dialog(item["spec"], item.get("eyebrow", "Protection"),
                          item.get("resolve"))
        return 1

    def _pump_next(self):
        self._active = None
        self._serve_next()
        return False

    def _notify_critical(self, events) -> None:
        from ui.notify_alert import CriticalSquare, CriticalEvents, \
            critical_filter
        square = getattr(self, "_crit_square", None)
        if square is None:
            square = CriticalSquare(CriticalEvents())
            self._crit_square = square
            self._crit_state = square.blocked     # CriticalEvents instance
        fresh = [t for t in critical_filter(events)
                 if t != self._crit_state.latest]
        for tool, text in fresh:
            shown = self._crit_state.add(tool, text)
            square.show(shown)

    def _notify_denies(self, events) -> None:
        from ui.notify_alert import NotifyAlert, BlockedQueue, parse_deny
        alert = getattr(self, "_alert", None)
        if alert is None:
            alert = NotifyAlert(BlockedQueue(dm.DATA_DIR))
            self._alert = alert
        seen = getattr(self, "_deny_seen", None)
        if seen is None:
            seen = set()
            self._deny_seen = seen
        for e in reversed(events):
            if not isinstance(e, dict) or e.get("from_tool") != "appfw":
                continue
            ts = e.get("ts", "")
            if ts in seen:
                continue
            seen.add(ts)
            parsed = parse_deny(e.get("text", ""))
            if parsed and parsed["action"] == "deny":
                alert.handle_deny(parsed["app"], parsed["host"])

    def pump_once(self) -> int:
        events = dm.read_events(dm.DATA_DIR / "events.jsonl", 2000)
        if not events:
            # The GUI runs as the desktop user; events.jsonl is root-owned.
            # When it is not group-readable the read fails silently and every
            # prompt vanishes (2026-10-27). status.json is 0640 root:<user
            # group> by contract, so use its recent-event snapshot instead of
            # going blind.
            try:
                import json
                snap = json.loads((dm.DATA_DIR / "status.json").read_text())
                events = snap.get("recent") or []
            except (OSError, ValueError):
                events = []
        return self.pump(events)

    def badge(self) -> int:
        try:
            answered = pending_ids(dm.DATA_DIR / "decisions.jsonl")
            from cli import _gather_specs
            specs, _ = _gather_specs()
            return sum(1 for s in specs if s["id"] not in answered)
        except Exception:
            return 0

    def _show_dialog(self, spec: dict, eyebrow="Protection", resolve=None):
        dlg = _decision_dialog(spec, modal=True, eyebrow=eyebrow,
                               on_learn=self._learn_now)
        parent = Gtk.Application.get_default()
        parent = parent.get_active_window() if parent else None
        if parent is not None:
            dlg.set_transient_for(parent)     # centre on the dashboard
            dlg.set_destroy_with_parent(True)
        dlg.connect("response", self._on_response, spec,
                    spec.get("options", []), resolve)
        dlg.present()

    def _on_response(self, dlg, response_id, spec, opts, resolve=None, *_a):
        dlg.destroy()
        dismissed = (not isinstance(response_id, int)
                     or response_id == Gtk.ResponseType.DELETE_EVENT
                     or response_id < 0 or response_id >= len(opts))
        if resolve is not None:            # app-firewall ask: hand back answer
            resolve(None if dismissed else response_id)
            GLib.timeout_add(200, self._pump_next)
            return
        if dismissed:
            GLib.timeout_add(200, self._pump_next)   # next one, stays pending
            return                       # dismissed: no answer recorded
        opt = opts[response_id]
        ok = record_answer(dm.DATA_DIR / "decisions.jsonl", spec["id"], opt["id"])
        if ok and self._tray:
            GLib.idle_add(self._tray.refresh_badge)
        GLib.timeout_add(200, self._pump_next)

    def _learn_now(self, minutes=15):
        """One click from the popup: stop asking, keep recording.

        The app firewall already had a learning window, but it lived in
        Settings — unreachable while a queue of prompts is on screen
        (owner report 2026-10-28: "an unlimited amount of popups and its
        infuriating"). Queued app-firewall prompts are dropped here
        because the policy will not raise new ones while learning is on.
        """
        try:
            from ui.settings import LearningStore
            if not LearningStore().start(minutes):
                return False
        except Exception:
            return False
        self._queue = [q for q in self._queue
                       if not str((q.get("spec") or {}).get("id", ""))
                       .startswith("appfw:")]
        try:
            if not DecisionBroker._notify_ready:
                DecisionBroker._notify_ready = bool(
                    _NotifyModule.init("greywatch"))
            if DecisionBroker._notify_ready:
                note = _NotifyModule.Notification.new(
                    "Greywatch",
                    f"Learning mode is on for {minutes} minutes. Unknown "
                    "programs are let through and recorded under Settings "
                    "→ App firewall.")
                note.show()
        except Exception:
            pass
        return True

    def _memo_get(self, key):
        now = time.monotonic()
        with self._recent_lock:
            for k in [k for k, v in self._recent.items() if v[0] <= now]:
                del self._recent[k]
            hit = self._recent.get(key)
        return hit[1] if hit else None

    def _memo_put(self, key, answer):
        with self._recent_lock:
            self._recent[key] = (time.monotonic() + self.ASK_MEMO_SECONDS,
                                 answer)

    # --- daemon → GUI ask bridge ---------------------------------------
    # The daemon runs as root with no display. When an unknown program
    # tries to connect it writes a request into appfw/asks/ and waits.
    # This poller picks that up and shows it in the SAME single popup
    # slot as every other decision, then writes the answer back.
    ASK_POLL_MS = 500
    ASK_FRESH_SECONDS = 20.0        # daemon gives up after 15 s

    def watch_appfw(self):
        """Start watching for app-firewall asks from the daemon."""
        self._asks_dir = pathlib.Path(dm.DATA_DIR) / "appfw" / "asks"
        self._answers_dir = self._asks_dir.parent / "answers"
        self._asked_files = set()
        GLib.timeout_add(self.ASK_POLL_MS, self._poll_appfw_asks)
        return True

    def _poll_appfw_asks(self):
        try:
            files = sorted(self._asks_dir.glob("*.json"))
        except OSError:
            return True
        for f in files[-1:]:              # the daemon asks one at a time
            name = str(f)
            if name in self._asked_files:
                continue
            try:
                doc = json.loads(f.read_text())
            except (OSError, ValueError):
                continue
            self._asked_files.add(name)
            if len(self._asked_files) > 200:
                self._asked_files = set(list(self._asked_files)[-100:])
            spec = doc.get("spec")
            if not isinstance(spec, dict) or not spec.get("options"):
                continue
            if not self._fresh(doc.get("ts")):
                continue
            self._enqueue_appfw(spec, f)
        return True

    def _enqueue_appfw(self, spec, req_path):
        def resolve(rid):
            opts = spec.get("options", [])
            if rid is None:               # dismissed → the safe default
                action, dur, host_op = "deny", "once", None
            else:
                ans = self._answer_from_response(rid, spec, opts)
                action = ans[0] if ans else "deny"
                dur = ans[1] if len(ans) > 1 else "once"
                host_op = ans[2] if len(ans) > 2 else None
            self._write_answer(req_path, action, dur, host_op)

        self._queue.append({"spec": spec, "eyebrow": "App firewall",
                            "resolve": resolve})
        self._serve_next()

    def _write_answer(self, req_path, action, duration, host_op):
        """Hand the verdict back to the daemon, atomically."""
        target = self._answers_dir / pathlib.Path(req_path).name
        tmp = target.with_name(target.name + ".tmp")
        doc = {"action": action, "duration": duration, "host_op": host_op}
        try:
            self._answers_dir.mkdir(parents=True, exist_ok=True)
            tmp.write_text(json.dumps(doc))
            os.replace(tmp, target)
        except OSError:
            try:
                tmp.unlink()
            except OSError:
                pass

    def ask_appfw(self, spec):
        """Queue an app-firewall prompt through the SAME single popup slot.

        The engine may ask about many connections at once; before this,
        each ask built its own dialog and the desktop filled with stacked
        boxes (owner report 2026-10-27: only one popup should ever exist).
        """
        key = (spec.get("subject"), spec.get("host"))
        recent = self._memo_get(key)
        if recent is not None:            # same app->site, seconds apart
            return recent
        done = threading.Event()
        box = {}

        def enqueue():
            opts = spec.get("options", [])

            def resolve(rid):
                if rid is None:
                    box["res"] = ("allow", "once")
                else:
                    box["res"] = self._answer_from_response(rid, spec, opts)
                self._memo_put(key, box["res"])
                done.set()
            self._queue.append({"spec": spec, "eyebrow": "App firewall",
                                "resolve": resolve})
            self._serve_next()
            return False

        GLib.idle_add(enqueue)
        if not done.wait(timeout=getattr(self, "ask_timeout", 90)):
            answer = ("allow", "once")
            self._memo_put(key, answer)
            return answer
        r = box.get("res")
        return r if isinstance(r, tuple) else ("allow", "once")

    @staticmethod
    def _answer_from_response(rid, spec, opts):
        if not isinstance(rid, int) or rid < 0 or rid >= len(opts):
            return ("allow", "once")
        opt = opts[rid]
        args = opt.get("args", [])
        dur = args[1] if len(args) > 1 else "once"
        act = args[0] if args and args[0] in ("allow", "deny") else "allow"
        host = spec.get("host", "")
        if "trust" in args or "trust-block" in args:
            from ui.settings import TrustList
            TrustList().add(host, "block" if "trust-block" in args else "allow")
            return act, "always", host      # operator matches the domain
        return act, dur

    _notify_ready = False

    def nudge(self, count: int):
        if not DecisionBroker._notify_ready:
            if not _NotifyModule.init("greywatch"):
                return
            DecisionBroker._notify_ready = True
        note = _NotifyModule.Notification.new(
            "greywatch", f"{count} pending decision(s): open the GUI", )
        note.show()
