"""The Network page (architecture v4, its own page).

Every device this machine sees, fingerprinted - MAC OUI, hostname if
the wall knew one, first and last seen, IP history - and the IP
analytics naming what flagged each address out of psad rows, fail2ban
rows, nft ledger rows and the intel feeds. The DNS monitor sits under
it: this machine's own domain lookups from the resolver's query log,
blocked hits named against the feed blocklist the wall serves.

The page is a skin over the CLI: `greywatch network` builds the
analytics store, `greywatch dnslog` reads the DNS store the daemon's
slow lane writes. NO DNS NEAR THE PUMP stands - nothing here touches
the daemon's beat.
"""

from __future__ import annotations

import threading
import time

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import GLib, Gtk

from ui import charts, cliapi, kit
from ui.widgets import (card, count_word, eyebrow, headline, meta, state_pill, sub)

_CACHE = {"at": 0.0, "doc": None}
_CACHE_S = 30.0
_LOCK = threading.Lock()


def _fresh_doc():
    """The cached document while it is younger than the window."""
    doc = _CACHE["doc"]
    if doc is not None and time.time() - _CACHE["at"] < _CACHE_S:
        return doc
    return None


def build(window) -> Gtk.Widget:
    scroll = Gtk.ScrolledWindow()
    scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
    scroll.set_vexpand(True)
    scroll.set_hexpand(True)
    page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
    page.add_css_class("gw-page")
    page._gw_window = window
    page.set_hexpand(True)
    page.set_vexpand(True)
    page.append(meta("Reading the network store..."))
    scroll.set_child(page)
    scroll._gw_body = page
    _start_read(page)
    return scroll


def refresh(page: Gtk.Widget) -> None:
    body = getattr(page, "_gw_body", None) or page
    doc = _fresh_doc()
    if doc is not None:
        fill(body, doc)
        return
    _start_read(body)


def _start_read(page: Gtk.Box) -> None:
    """Read the store on a worker; the page paints when it lands."""
    def work():
        try:
            doc = _netmon_store()
        except Exception:                  # noqa: BLE001
            doc = None
        GLib.idle_add(fill, page, doc)
        return None

    thread = threading.Thread(target=work, daemon=True,
                              name="gw-network-read")
    page._gw_read_thread = thread
    thread.start()


def fill(page: Gtk.Box, report) -> bool:
    _clear(page)
    _paint(page, report or {})
    return False


def _clear(box: Gtk.Box) -> None:
    child = box.get_first_child()
    while child is not None:
        nxt = child.get_next_sibling()
        box.remove(child)
        child = nxt


def _paint(page: Gtk.Box, report) -> None:
    counts = (report or {}).get("counts") or {}

    head = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
    head.append(headline("Network"))
    level = "ok"
    if not report or not counts:
        level = "warn"
    elif counts.get("flagged"):
        level = "fail"
    head.append(state_pill(*_mark(level)))
    head.set_halign(Gtk.Align.START)
    page.append(head)
    built = str((report or {}).get("built_at") or "")
    page.append(meta(
        f"Analytics from {built.split('T')[0] if built else 'unknown date'}. "
        f"{count_word(counts.get('devices', 0), 'device')} seen; "
        f"{count_word(counts.get('flagged', 0), 'address', 'addresses')} "
        "flagged by psad, fail2ban, the nft ledger or the intel feeds."))

    page.append(_devices_card(report))
    page.append(_flagged_card(report))
    page.append(_wot_card())
    page.append(_dns_card(page))


def _mark(level: str) -> tuple[str, str]:
    word = {"ok": "Watching", "warn": "No analytics yet",
            "fail": "Flagged addresses present"}[level]
    return word, level


def _netmon_store():
    with _LOCK:
        cached = _fresh_doc()
        if cached is not None:
            return cached
        live = cliapi.jcall("network")
        doc = live or cliapi.read_state("network-analytics.json")
        if doc:
            _CACHE.update({"at": time.time(), "doc": doc})
        return doc


def _devices_card(report) -> Gtk.Widget:
    devices = (report or {}).get("devices") or {}
    if not devices:
        return card(eyebrow("Devices"),
                    sub("No devices yet. Arpwatch lists a device once it "
                        "sends traffic through the watched interface."))
    rows = []
    for mac, row in sorted(devices.items(),
                           key=lambda kv: kv[1].get("last_seen") or "",
                           reverse=True):
        vendor = str(row.get("vendor") or "")
        label = MAC_NAMES.get(mac, vendor or mac)
        shown_mac = "unresolved" if mac == "unknown-mac" else mac
        rows.append([shown_mac, label, " ".join(row.get("ips") or []),
                     _date(row.get("first_seen")),
                     _date(row.get("last_seen")),
                     _whats(row.get("what"))])
    tree, store = _tree(columns=(
        ("Address", 150), ("Vendor", 150), ("IP", 120),
        ("First seen", 150), ("Last seen", 150), ("Event", 220)), rows=rows)
    _ = store
    card_rows = [tree]
    stamps = [str(w.get("when") or "")
              for row in devices.values()
              for w in (row.get("what") or [])]
    grid = charts.heatmap_cells(stamps)
    if any(sum(row) for row in grid):
        card_rows.append(charts.sparkline(
            [g[6] for g in grid], w=260, h=40))
    return card(eyebrow(f"Devices - {count_word(len(devices), 'device')} "
                        "seen on the interface"),
                sub("Fingerprinted by MAC OUI, with first seen, last "
                    "seen and IP history."),
                *card_rows)


def _flagged_card(report) -> Gtk.Widget:
    ips = (report or {}).get("ips") or {}
    flagged = {ip: row for ip, row in ips.items() if row.get("flagged_by")}
    if not flagged:
        return card(eyebrow("Flagged addresses"),
                    sub("No address is flagged by any lane or feed."),
                    cls="gw-card gw-card-quiet")
    rows = []
    for ip, row in sorted(flagged.items(),
                          key=lambda kv: kv[1].get("last_seen") or "",
                          reverse=True):
        rows.append([ip, ", ".join(row.get("flagged_by") or []),
                     _date(row.get("last_seen")),
                     _whats(row.get("what"))])
    tree, store = _tree(columns=(
        ("Address", 130), ("Flagged by", 220), ("Last seen", 150),
        ("What", 300)), rows=rows)
    chips = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
    for ip, row in list(sorted(flagged.items(),
                               key=lambda kv: kv[1].get("last_seen") or "",
                               reverse=True))[:4]:
        for by in (row.get("flagged_by") or [])[:4]:
            chips.append(kit.chip(by, "fail"))
    return card(eyebrow(f"Flagged addresses - {count_word(len(flagged), 'address', 'addresses')}"),
                sub("What flagged each one: a psad row, a fail2ban "
                    "row, an nft block, or a hit on an intel feed."),
                chips if any(True for _c in chips) else
                meta("No flagged addresses to name."), tree)


def _dns_card(page) -> Gtk.Widget:
    doc = cliapi.read_state("dnslog.json")
    if not doc or not (doc.get("counts") or {}):
        return card(eyebrow("DNS"),
                    sub("The DNS store is written by the daemon's slow "
                        "lane; the first pass lands five minutes after a "
                        "restart."))
    counts = doc.get("counts") or {}
    if not doc.get("log_queries_enabled"):
        return card(eyebrow("DNS"),
                    sub(f"The resolver keeps no query log yet. "
                        f"{doc.get('log_how') or 'log-queries is off'}. "
                        "One sync line turns it on; the store fills on "
                        "the next slow-lane pass."))
    if counts.get("queries", 0) == 0:
        return card(eyebrow("DNS"),
                    sub("No query rows yet. The query log just started; "
                        "the next slow-lane pass fills this."))
    domains = doc.get("domains") or {}
    rows = []
    for name, row in sorted(domains.items(),
                            key=lambda kv: kv[1].get("last") or "",
                            reverse=True)[:200]:
        rows.append([name, str(row.get("queries", 0)),
                     _date(row.get("last")),
                     "blocked" if row.get("blocked") else "passed"])
    tree, store = _tree(columns=(
        ("Domain", 260), ("Queries", 80), ("Last seen", 150),
        ("Result", 90)), rows=rows)
    _ = page
    return card(
        eyebrow(f"DNS - {count_word(counts.get('domains', 0), 'domain')}, "
                f"{count_word(counts.get('blocked_hits', 0), 'block')} "
                "on the blocklist"),
        sub("This machine's own lookups, matched against the blocklist "
            "the feeds render for dnsmasq. Whole-network DNS joins when "
            "the router hands this machine the DNS role."),
        tree)


# -- small helpers -----------------------------------------------------

MAC_NAMES = {"unknown-mac": "unresolved"}


def _wot_card() -> Gtk.Widget:
    """The web of trust: the enforced blocklists this machine serves and
    the firewall layer that auto-drops listed netblocks. Reads the feeds
    lane's intel-web.json report; every number there is per-source, with
    the trust verdict counted, not implied."""
    doc = cliapi.read_state("intel-web.json")
    if not doc or not doc.get("sources"):
        return card(eyebrow("Web of trust"),
                    sub("No feed report yet. The feeds lane writes one on "
                        "its first run; watch the Tools page for the "
                        "lane's state."),
                    cls="gw-card gw-card-quiet")
    totals = doc.get("totals") or {}
    rows = []
    firewall = doc.get("firewall") or {}
    for name, src in (doc.get("sources") or {}).items():
        if not src.get("rows"):
            continue
        rows.append([
            name,
            f"tier {src.get('tier', '?')}",
            str(src.get("curator") or ""),
            str(src.get("rows", 0)),
            str(src.get("enforced", 0)),
            str(src.get("held", 0)),
            str(src.get("state") or "unknown")])
    parts = [eyebrow("Web of trust - "
                     f"{count_word(totals.get('enforced', 0), 'row', 'rows')} "
                     "enforced")]
    parts.append(sub(
        "Tier-1 curators enforce alone; tier-2 lists need an independent "
        "second source. Held rows stay in the cache but never reach the "
        "blocklist."))
    if rows:
        tree, store = _tree(columns=(
            ("Source", 150), ("Trust", 70), ("Curator", 110),
            ("Rows", 70), ("Enforced", 80), ("Held", 60),
            ("Last pull", 100)), rows=rows)
        _ = store
        parts.append(tree)
    else:
        parts.append(meta("No feed rows survived validation; the report "
                          "names why per source."))
    if firewall.get("count"):
        parts.append(meta(
            f"Firewall layer: {firewall.get('summary') or firewall['count']} "
            + ("enforced in the gw_intel nft table."
               if firewall.get("loaded") else
               "stored; the daemon re-applies it at its next boot.")))
    elif firewall:
        parts.append(meta("Firewall layer: no enforced IP rows to drop."))
    return card(*parts)

_WHAT_GLUE = "; "


def _whats(rows) -> str:
    parts = []
    for row in rows or []:
        piece = str((row or {}).get("what") or "")
        if piece and piece not in parts:
            parts.append(piece[:90])
    return _WHAT_GLUE.join(parts[:3])


def _date(stamp) -> str:
    s = str(stamp or "")
    if "T" in s:
        return s.replace("T", " ")[:19]
    return s or "never"


def _tree(columns, rows=()) -> tuple[Gtk.ScrolledWindow, Gtk.ListStore]:
    store = Gtk.ListStore(*[str] * len(columns))
    for row in rows:
        store.append(row)
    tree = Gtk.TreeView(model=store, activate_on_single_click=False)
    tree.set_enable_search(True)
    tree.set_hexpand(True)
    tree.set_vexpand(True)
    last = len(columns) - 1
    for i, (title, width) in enumerate(columns):
        cell = Gtk.CellRendererText()
        col = Gtk.TreeViewColumn(title, cell, text=i)
        col.set_sizing(Gtk.TreeViewColumnSizing.FIXED)
        col.set_fixed_width(width)
        if i == last:
            # the last column takes the remaining width, so a wide
            # window reads as one table rather than a small island
            col.set_expand(True)
        tree.append_column(col)
    scroll = Gtk.ScrolledWindow()
    scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
    scroll.set_min_content_height(220)
    scroll.set_hexpand(True)
    scroll.set_vexpand(True)
    scroll.set_child(tree)
    # the rows ride the widget too: the pins read the tables here,
    # because a tree cell's text is not a widget label
    scroll._gw_rows = [list(r) for r in rows]
    return scroll, store
