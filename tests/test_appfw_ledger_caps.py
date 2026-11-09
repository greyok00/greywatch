"""ITER-0001 pins: every ledger the app owns has a stated growth
policy, and the learning ledger meets the same planted-name standard
the daemon's own ledgers carry (GW-02 precedent: the engine runs as
root in a group-shared dir; a plain append/replace follows anything a
group member plants)."""
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


from appfw.policy import Policy, KEEP_LEDGER_LINES


def _conn(host, port=443):
    import types
    return types.SimpleNamespace(process_path="/usr/bin/app", host=host,
                                 dst_port=port, protocol="tcp")


def _learning_on(tmp_path):
    import time
    (tmp_path / "learning.json").write_text(
        json.dumps({"until": time.time() + 120}))


def test_learning_ledger_trim_keeps_the_newest(tmp_path):
    """The stated cap: past MAX_LEDGER_BYTES the newest
    KEEP_LEDGER_LINES records survive, older ones are dropped."""
    _learning_on(tmp_path)
    policy = Policy(tmp_path)
    total = 2400
    for i in range(total):
        policy.record_learned(_conn(f"host{i}.example"))
    ledger = (tmp_path / "learning-seen.jsonl").read_text().splitlines()
    assert len(ledger) <= KEEP_LEDGER_LINES, len(ledger)
    assert "host%d.example" % (total - 1) in ledger[-1]   # newest kept
    assert "host0.example" not in "\n".join(ledger[:50])  # oldest dropped


def test_learning_ledger_refuses_a_planted_symlink(tmp_path):
    """A group member planting learning-seen.jsonl as a symlink must
    never have root append through it: the victim file stays byte-identical
    and the ledger write is refused (OSError swallowed by the same
    except that guards the writer)."""
    victim = tmp_path / "victim.txt"
    victim.write_text("VICTIM\n")
    (tmp_path / "learning-seen.jsonl").symlink_to(victim)
    _learning_on(tmp_path)
    policy = Policy(tmp_path)
    policy.record_learned(_conn("planted.example"))     # must not raise
    assert victim.read_text() == "VICTIM\n"
    # the planted name was never followed and never created as a file
    assert (tmp_path / "learning-seen.jsonl").is_symlink()


def test_malformed_log_cap_keeps_the_newest_2000(tmp_path):
    """The malformed diagnostic log's disk cap: past 1 MB only the
    newest 2,000 lines survive the flush that grew it."""
    from tests.test_daemon_loop import mk_daemon
    d = mk_daemon(tmp_path)
    log = d.data_dir / "malformed.log"
    log.write_text("PAD\n" * (260_000))     # ~1.04 MB: just over the 1 MB disk cap
    import os as _os
    _os.chmod(log, 0o600)   # the daemon's own files are 0600 (append_checked create_mode); a group-writable planted file is refused, never trimmed
    d.consume("responderd", "{definitely-not-json \"BATCHMARK\"")
    d.flush_malformed()
    lines = log.read_text().splitlines()
    assert len(lines) <= 2000, len(lines)
    assert any("BATCHMARK" in ln for ln in lines[-3:])   # newest kept
