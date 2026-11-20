from __future__ import annotations

import pathlib

from gi.repository import GLib
from ui import cliapi


def signature(*names: str) -> str:
    parts = []
    for name in names:
        try:
            st = pathlib.Path(cliapi.state_path(name)).stat()
            parts.append(f"{name}:{st.st_mtime_ns}:{st.st_size}")
        except OSError:
            parts.append(f"{name}:-")
    return "|".join(parts)


def restore_scroll(scroller) -> None:
    adjustment = scroller.get_vadjustment()
    value = adjustment.get_value()

    def put():
        adjustment.set_value(value)
        return False

    GLib.idle_add(put)
