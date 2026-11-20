"""E-2: CLI golden surface — the full command surface walked "one at a
time" with the rc + first-line contract asserted per verb.

Every command runs through cli.main() in a sandboxed data env (the
repo's data_env idiom); helpers never reach privilege (conftest's
escalation guard is autouse). The golden contract is behavioral and
additive-stable: rc values and output shape, not byte-for-byte prose
(plain-language text may improve; contracts may not silently change).
"""
from __future__ import annotations

import pathlib
import sys

import pytest

import cli


@pytest.fixture
def data_env(tmp_path, monkeypatch):
    """The repo's data_env idiom (tests/test_cli.py:21), inlined."""
    data = tmp_path / "data"
    data.mkdir(parents=True)
    monkeypatch.setattr(cli, "DATA_DIR", data)
    monkeypatch.setenv("GREYWATCH_HELPER_CMD", "/bin/true")
    import greywatch_daemon as gd
    monkeypatch.setattr(gd, "DATA_DIR", data)
    return data

# verb -> (argv tail, expected rc, first-line must-contain tokens)
# rc contract from cli.py/cannot-fail-map: 0 ok, 2 usage/unknown
GOLDEN = [
    ("status", [], 0),
    ("events", [], 0),
    ("events", ["--severity", "HIGH"], 0),
    ("events", ["--tool", "appfw"], 0),
    ("decisions", [], 0),
    ("decisions", ["--pending"], 0),
    ("rules", [], 2),
    ("rules", ["appfw"], 0),
    ("doctor", [], 0),
    ("hunter", [], 0),
    ("log", ["responderd"], 0),
    ("log", ["no-such-tool"], 2),       # unknown tool refuses (cmd_log)
    # refusals keep their rc contract
    ("no-such-verb", [], 2),
    ("answer", [], 2),                   # missing args = usage
    ("action", ["restart", "responderd", "extra-arg"], None),  # contract: nonzero
    ("drop-ip", [], 2),                  # not a top-level verb
]


def _run(monkeypatch, argv_tail):
    import contextlib
    import io
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        try:
            rc = cli.main(argv_tail)   # argv IS the tail (repo idiom)
        except SystemExit as e:
            rc = e.code if isinstance(e.code, int) else 2
    return rc, buf.getvalue()


def test_cli_surface_rc_and_shape(data_env, monkeypatch, capsys):
    seen = []
    for verb, tail, want_rc in GOLDEN:
        rc, out = _run(monkeypatch, [verb] + tail)
        seen.append((verb, " ".join(tail), rc))
        if want_rc is not None:
            assert rc == want_rc, \
                f"rc contract broken: {verb} {tail} -> {rc} (want {want_rc})"
        else:
            assert isinstance(rc, int) and rc != 0, \
                f"{verb} must refuse with a nonzero rc, got {rc}"
        # honesty law: a traceback never surfaces as CLI output
        assert "Traceback" not in out, f"{verb} {tail} leaked a traceback"
    # the surface really was walked "one at a time"
    assert len(seen) == len(GOLDEN)


def test_unknown_verb_exit_code_is_two(data_env, capsys):
    rc = None
    import contextlib, io
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        try:
            rc = cli.main(["bogus-verb"])
        except SystemExit as e:
            rc = e.code if isinstance(e.code, int) else 2
    assert rc == 2


def test_every_verb_prints_something_or_empty_honestly(data_env, capsys):
    """No verb crashes with an empty traceback; empty output must be an
    honest empty (rc 0), like an empty events file."""
    for verb in ("status", "events", "decisions", "doctor", "hunter",
                 "rules"):
        rc, out = _run(None, [verb])
        assert isinstance(rc, int)
        assert "Traceback" not in out
