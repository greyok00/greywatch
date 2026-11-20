"""Pins for the Advanced dropdown and the per-tool desks: one row per
tool surface, one desk per tool carrying its state, feed, digest and
the verbs it answers."""

from __future__ import annotations

import json
import pathlib

import pytest

from tests.test_ui_v4 import _ShellStub, _all_texts
from tests.test_ui_network import _tree_rows
from tests.test_ui_tool_desk import _pump


TOOL_JSON = {
    "tool": "clamav", "label": "ClamAV", "unit": "clamav-daemon.service",
    "state": "GREEN", "last_event": "2026-11-15T08:20:03+00:00",
    "events": [
        {"from_tool": "clamav", "severity": "INFO",
         "text": "check-in: alive, running normally",
         "ts": "2026-11-15T08:20:03+00:00"},
        {"from_tool": "clamav", "severity": "MEDIUM",
         "text": "scan found one row and quarantined it",
         "ts": "2026-11-15T08:21:03+00:00"},
    ]}


@pytest.fixture
def advanced(tmp_path, monkeypatch):
    monkeypatch.setenv("GREYWATCH_DATA_DIR", str(tmp_path / "state"))
    import ui.advanced as advanced
    from ui import cliapi

    def fake_call(*args, timeout=30.0):
        if args[0] == "tool":
            return 0, json.dumps(TOOL_JSON), ""
        return 0, "", ""

    monkeypatch.setattr(cliapi, "jcall",
                        lambda *a, timeout=30.0: (
                            TOOL_JSON if a[0] == "tool" else None))
    return advanced, cliapi


def test_advanced_has_three_named_groups(advanced):
    advanced_mod, _cli = advanced
    assert [group[0] for group in advanced_mod.GROUPS] == [
        "Network and access", "Scanning and integrity",
        "System and audit"]
    assert sum(len(group[1]) for group in advanced_mod.GROUPS) == \
        len(advanced_mod.TOOLS)
    assert {label for _caption, labels in advanced_mod.GROUPS
            for label in labels} == \
        {label for label, _ids, _digest in advanced_mod.TOOLS}


def test_one_row_per_tool_surface(advanced):
    advanced_mod, _cli = advanced
    shell = _ShellStub()
    rows = advanced_mod.build_rows(shell)
    labels = [b.get_label() for b in rows]
    assert len(labels) == len(advanced_mod.TOOLS)
    assert "Virus Scan" in labels
    assert "App Firewall" in labels


def test_desk_carries_state_feed_and_verbs(advanced, monkeypatch):
    advanced_mod, cli = advanced
    from ui import tooldesk
    page = tooldesk.build(_ShellStub(), "Virus Scan",
                          ("clamav", "freshclam"), "clamav")
    _pump()
    texts = " ".join(_all_texts(getattr(page, "_gw_body", page)))
    assert "2 of 2 tools live" in texts
    rows = _tree_rows(page)
    assert any("scan found one row and quarantined it" in " ".join(r)
               for r in rows)
    assert "greywatch tool clamav" in texts


def test_digest_reads_the_tool_digest_file(advanced):
    advanced_mod, _cli = advanced
    from ui import tooldesk
    page = tooldesk.build(_ShellStub(), "Virus Scan",
                          ("clamav", "freshclam"), "clamav")
    texts = " ".join(_all_texts(getattr(page, "_gw_body", page)))
    # the real digest ships for clamav on this tree
    clamav_digest = (pathlib.Path(advanced_mod.__file__).parents[1]
                     / "tool-digests" / "clamav.md")
    if clamav_digest.exists():
        assert "tool digest" in texts.lower()
    else:
        assert "no digest file" in texts


def test_unreadable_tool_says_so(advanced, monkeypatch):
    advanced_mod, cli = advanced
    monkeypatch.setattr(cli, "jcall", lambda *a, **k: None)
    from ui import tooldesk
    page = tooldesk.build(_ShellStub(), "Virus Scan",
                          ("clamav",), "clamav")
    _pump()
    texts = " ".join(_all_texts(getattr(page, "_gw_body", page)))
    assert "Could not read right now" in texts


def _children(w) -> list:
    out = []
    c = w.get_first_child() if hasattr(w, "get_first_child") else None
    while c is not None:
        out.append(c)
        out.extend(_children(c))
        c = c.get_next_sibling()
    return out
