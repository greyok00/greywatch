# ui/actions.py
from __future__ import annotations

import threading

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import GLib, Gtk


class ActionError(ValueError):
    pass


def _window_of(parent):
    if isinstance(parent, Gtk.Window):
        return parent
    if parent is not None and hasattr(parent, "get_root"):
        root = parent.get_root()
        if isinstance(root, Gtk.Window):
            return root
    return None


def ask(parent, title, body, accept="Continue") -> bool:
    window = _window_of(parent)
    dialog = Gtk.Dialog(title=title, transient_for=window, modal=True)
    dialog.add_button("Cancel", Gtk.ResponseType.CANCEL)
    dialog.add_button(accept, Gtk.ResponseType.OK)
    dialog.set_default_response(Gtk.ResponseType.OK)
    label = Gtk.Label(label=body)
    label.set_wrap(True)
    label.set_max_width_chars(72)
    label.set_xalign(0.0)
    dialog.get_content_area().append(label)
    result = {"ok": False}
    closed = {"done": False}
    loop = GLib.MainLoop()

    def finish(ok=False):
        if closed["done"]:
            return
        closed["done"] = True
        result["ok"] = ok
        loop.quit()

    def answered(_dialog, response):
        finish(response == Gtk.ResponseType.OK)
        dialog.destroy()

    def vanished(_widget):
        finish(False)

    # GtkWindow's "destroy" is a cleanup-phase signal: this GTK emits it at
    # finalization, not when gtk_window_destroy drops the surface, so a
    # parent torn down with references held sends no "destroy" at all.
    # "unrealize" is the reliable teardown marker; both are hooked and the
    # closed flag makes the second one a no-op.
    handlers = []
    for widget in (dialog, window):
        if widget is None:
            continue
        for signal_name in ("destroy", "unrealize"):
            handlers.append((widget, widget.connect(signal_name, vanished)))

    dialog.connect("response", answered)
    try:
        dialog.present()
        loop.run()
    finally:
        for widget, handler in handlers:
            try:
                widget.disconnect(handler)
            except (TypeError, RuntimeError):
                pass
    return result["ok"]


def action_button(text, handler, *, cls="gw-secondary", parent=None,
                  confirm=None) -> Gtk.Button:
    if not callable(handler):
        raise ActionError("an action button needs a callable handler")
    button = Gtk.Button(label=text)
    for name in str(cls or "").split():
        button.add_css_class(name)
    button._gw_handler = handler

    def clicked(_button):
        if not button.get_sensitive():
            return
        if confirm and not ask(parent, text, confirm, accept=text):
            return
        handler()

    button.connect("clicked", clicked)
    return button


def run_async(button, work, on_done, *, pending="Working...", done=None):
    if not button.get_sensitive():
        return
    original = button.get_label()
    button.set_label(pending)
    button.set_sensitive(False)

    def finish(result):
        button.set_label(done or original)
        button.set_sensitive(True)
        on_done(result)
        return False

    def worker():
        try:
            result = work()
        except Exception as exc:                  # noqa: BLE001
            result = exc
        GLib.idle_add(finish, result)

    threading.Thread(target=worker, daemon=True,
                     name="gw-action").start()
