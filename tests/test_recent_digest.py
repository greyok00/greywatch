"""recent_digest: the bounded, public tail of recent events the daemon
publishes inside status.json. The raw event store is root-owned (0600),
so the user-run desktop app can only read the world-readable status
file — that digest is what the "Recent" short log resolves from when
the direct read yields nothing."""
from greywatch_daemon import recent_digest
from ui.models import recent_rows


def _ev(n):
    return {"ts": f"2026-10-26T0{min(n, 9)}:00:00Z", "text": "audit finished",
            "from_tool": "aide", "severity": "INFO", "id": f"e{n}"}


def test_digest_is_a_bounded_recent_tail():
    evs = [_ev(i) for i in range(100)]
    d = recent_digest(evs)
    assert len(d) == 40
    assert d[0]["id"] == "e60"
    assert d[-1]["id"] == "e99"


def test_digest_honors_smaller_caps_and_empty_input():
    assert [e["id"] for e in recent_digest([_ev(i) for i in range(5)],
                                           cap=2)] == ["e3", "e4"]
    assert recent_digest([]) == []


def test_gui_rows_compose_from_the_digest():
    rows = recent_rows(recent_digest([_ev(i) for i in range(10)]), 6)
    assert 1 <= len(rows) <= 6
    assert rows[0].get("id") == "e9"      # newest first, like the direct path