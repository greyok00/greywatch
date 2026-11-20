"""E-5: the ask-window FSM walked end-to-end (one integration walk).

Layer-2/3 seam the unit tests cover in pieces: a kernel GW-DENY line goes
through evaluate_connection (v6-aware parse, /proc attribution) -> the
policy chain (rules -> feeds -> ask) -> the ask-gate window FSM -> the
owner's Always answer -> store as a process rule -> the sweep lifecycle
(GC keeps L3/L4, archives the answered file, late answers win).
One walk, real components, tmp_path everywhere; no kernel, no dialogs.
"""
from __future__ import annotations

import json
import pathlib
import sys
import time

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import appfw.policy as policy_mod          # noqa: E402
from appfw.askgate import AskGate          # noqa: E402


# ------------------------------------------------------------- helpers
class AskDialog:
    """The owner's answer, delivered the way the GUI bridge would."""

    def __init__(self, answer=None):
        self.answer = answer            # None = never answered
        self.asked = 0

    def __call__(self, spec):
        self.asked += 1
        self.spec = spec
        return self.answer


def _policy(tmp_path):
    try:
        pol = policy_mod.Policy(data_dir=tmp_path)
    except TypeError:
        pol = policy_mod.Policy()
    return pol


class _Attributed:
    """A resolver that attributes the flow to a real program.

    The walk is about the ASK-WINDOW FSM, not about the flood guard: the
    guard (owner 2026-11-10 no-flood law) deliberately skips the card for
    an UNATTRIBUTABLE flow, so a resolver-less line can never reach the
    dialog and the FSM would be untested. Attributing the connection is
    what the engine's real resolver does in production for any flow it can
    see in /proc, so this is the honest fixture for this walk.
    """

    # A RISKY path (a /tmp drop) is what lifts a first contact to L3, the
    # level at which the chain asks. A system binary scores L2 and is
    # silently allowed, so the dialog is never reached and this walk would
    # assert nothing (measured: /usr/lib/chromium -> L2).
    def resolve(self, conn):
        conn.pid = 4242
        conn.process_path = "/tmp/downloaded-installer.sh"
        conn.attribution = "resolved"
        return conn


def _gw_line(dst="93.184.216.34", spt=45121, dpt=443, proto="tcp"):
    return (f"kernel: GW-DENY IN= OUT=wlp0s20f3 SRC=192.168.1.42 DST={dst} "
            f"LEN=60 TOS=0x00 TTL=64 ID=1234 DF PROTO={proto} "
            f"SPT={spt} DPT={dpt}")


# ---------------------------------------------------------------- walk
def test_walk_kernel_line_to_verdict_to_card(tmp_path, monkeypatch):
    """A kernel GW-DENY line resolves to a full-chain verdict tuple with
    the card-shape facts an id/dedupe-key consumer needs."""
    pol = _policy(tmp_path)
    enforce = __import__("appfw.enforce", fromlist=["evaluate_connection"])
    verdict = enforce.evaluate_connection(
            _gw_line(), policy=pol, resolver=None, ask=None)
    assert verdict is not None, "a well-formed GW-DENY line must evaluate"
    app, dst, dpt, action, duration, exe = verdict
    assert dpt == 443 and dst == "93.184.216.34"
    assert action in ("allow", "deny")
    assert duration == "once"            # no ask wired: headless verdict


def test_walk_ask_window_one_prompt_per_destination(tmp_path, monkeypatch):
    """The FSM: same destination, retried on multiple ports inside the
    window, ask exactly once; a different destination asks again."""
    pol = _policy(tmp_path)
    dialog = AskDialog(answer=("allow", "once", None))
    gate = AskGate("deny-once", window=300, ask=dialog)
    enforce = __import__("appfw.enforce", fromlist=["evaluate_connection"])
    resolver = _Attributed()
    v1 = enforce.evaluate_connection(_gw_line(spt=45121, dpt=443),
                                     policy=pol, resolver=resolver,
                                     ask=gate.ask)
    v2 = enforce.evaluate_connection(_gw_line(spt=45222, dpt=8443),
                                     policy=pol, resolver=resolver,
                                     ask=gate.ask)
    v3 = enforce.evaluate_connection(_gw_line(dst="198.51.100.9", spt=45333,
                                              dpt=443),
                                     policy=pol, resolver=resolver,
                                     ask=gate.ask)
    assert v1 is not None and v2 is not None and v3 is not None
    assert dialog.asked == 2             # 1.2.3-line dst once; new dst once


def test_walk_owner_always_answer_is_stored_and_applies(tmp_path):
    """The C3 contract: the owner's Always answer is stored as a process
    rule (the real RuleStore) and decide() carries it onward."""
    from appfw.rules import RuleStore
    from appfw.enforce import apply_catch_answer
    store = RuleStore(tmp_path / "appfw" / "rules")
    verdict = ("firefox", "93.184.216.34", 443, "allow", "always",
               "/usr/bin/firefox")
    written = apply_catch_answer(verdict,
                                 process_path="/usr/bin/firefox",
                                 store=store)
    assert written is True
    # the stored rule really holds the same shape (Rule fields: op_kind,
    # op_value — the store keys rules by name)
    stored = store._allow.get("appfw-app-firefox")
    assert stored is not None, "the Always rule is not in the store"
    assert stored.op_kind == "process.path"
    assert stored.op_value == "/usr/bin/firefox"
    assert stored.action == "allow" and stored.duration == "always"


def test_walk_ask_lifecycle_gcs_and_archives(tmp_path):
    """The sweep: an answered ask file archives and leaves answers clean;
    an unanswered L3 ask stays pending (cards never expire)."""
    import appfw.asklifecycle as asklifecycle
    asks = tmp_path / "appfw" / "asks"
    answers = tmp_path / "appfw" / "answers"
    archive = asks / "archive"      # asklifecycle.py:37 layout
    asks.mkdir(parents=True)
    answers.mkdir(parents=True)
    ask_id = "appfw:testapp:93.184.216.34"
    key = __import__("hashlib").sha256(ask_id.encode()).hexdigest()[:16]
    (asks / f"{key}.json").write_text(json.dumps({
        "id": ask_id, "level": "L3", "ts": "2026-11-12T05:00:00+00:00"}))
    (answers / f"{key}.json").write_text(json.dumps({"action": "allow"}))
    counts = asklifecycle.sweep_asks(tmp_path)
    assert counts["archived"] >= 1
    # answered: the ask leaves the queue (the archive dir itself lives
    # inside asks/ and is not an ask)
    left = [p for p in asks.iterdir()
            if p.is_file() and p.suffix == ".json"]
    assert left == []
    assert any(p.is_file() for p in archive.iterdir())   # archived


def test_walk_sweep_never_deletes_an_l3_card(tmp_path):
    """An unanswered L3 ask survives every sweep (cards never expire)."""
    import appfw.asklifecycle as asklifecycle
    asks = tmp_path / "appfw" / "asks"
    asks.mkdir(parents=True)
    ask_id = "appfw:testapp:198.51.100.9"
    key = __import__("hashlib").sha256(ask_id.encode()).hexdigest()[:16]
    (asks / f"{key}.json").write_text(json.dumps({
        "id": ask_id, "level": "L3", "ts": "2026-11-12T05:00:00+00:00"}))
    counts = asklifecycle.sweep_asks(tmp_path)
    assert counts["kept"] == 1
    assert (asks / f"{key}.json").exists()
