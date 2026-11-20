"""The appfw wizard explains in full sentences and never scrolls.

Owner 2026-11-10: "it doesn't explain that well and still scrolls". The
pages must carry real explanatory copy (an intro that says what a rule
changes, an action page that says what BLOCK and ALLOW mean, a program
page that says where the list comes from), and the hints stop being
48-character crumbs (the cramped width the owner means by "doesn't
explain"). The GW-174 no-scroll law stays pinned by the fit tests.
"""
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

gi = pytest.importorskip("gi")
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk  # noqa: E402

from ui import wizard as W  # noqa: E402


def _labels(widget):
    c = widget.get_first_child()
    while c is not None:
        if isinstance(c, Gtk.Label):
            yield c.get_text() or ""
        yield from _labels(c)
        c = c.get_next_sibling()


def _page_texts(wz):
    return list(_labels(wz.get_nth_page(i))
                for i in range(wz.get_n_pages())), \
           [wz.get_nth_page(i) for i in range(wz.get_n_pages())]


def test_appfw_intro_explains_what_a_rule_changes():
    wz = W.RuleWizard("appfw", parent=None)
    texts, _pages = _page_texts(wz)
    flat = "\n".join(s for lst in texts for s in lst)
    assert "answers for you in advance" in flat
    assert "no popup" in flat
    wz.destroy()


def test_appfw_action_page_defines_block_and_allow():
    wz = W.RuleWizard("appfw", parent=None)
    texts, pages = _page_texts(wz)
    what = [p for p, _t in zip(pages, texts)
            if "What should happen?" in _one_text(p)]
    assert what, "the action page is missing"
    flat = "\n".join(t for p in what for t in _labels(p))
    assert "never connects" in flat and "the safe pick" in flat
    assert "connects freely" in flat
    wz.destroy()


def test_appfw_program_page_says_the_list_is_real():
    wz = W.RuleWizard("appfw", parent=None)
    texts, pages = _page_texts(wz)
    which = [p for p, _t in zip(pages, texts)
             if "Which program?" in _one_text(p)]
    assert which, "the program page is missing"
    flat = "\n".join(t for p in which for t in _labels(p))
    assert "desktop menu" in flat
    wz.destroy()


def _one_text(page):
    return "\n".join(_labels(page))


def test_hints_stop_being_crumbs():
    """The 48-char hint width is the 'shoved into a tiny box' copy; a
    full sentence needs the wider measure (the width laws still cap the
    window at measure time)."""
    h = W._hint("If the program you want is missing, click Scan again - "
                "the list is rebuilt from what this computer can see.")
    assert h.get_max_width_chars() >= 64
