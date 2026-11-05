# tests/test_assistant_events.py
"""Event grouping and noise classification.

The live log had 21,207 rows and 7,793 distinct lines, and 90 "High"
quarantine rows that were all the same harmless test file. Every answer
that counts rows has to know the difference, so these tests pin the
buckets and the collapse.
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from assistant import events  # noqa: E402


def _row(tool, text, sev="HIGH", ts="2026-10-29T10:00:00+00:00"):
    return {"from_tool": tool, "severity": sev, "text": text, "ts": ts}


def test_pytest_fixture_is_noise():
    row = _row("responderd", "quarantine: /tmp/pytest-of-grey/pytest-34/"
                             "test_yara_hit_test0/sample.bin (sha256:275a021b) "
                             "tmpfs:Eicar-Test-Signature")
    hit = events.classify(row)
    assert hit["bucket"] == events.NOISE
    assert events.is_noise(row)


def test_eicar_signature_alone_is_noise():
    row = _row("yara-watch", "YARA matched Eicar-Test-Signature in /tmp/x")
    assert events.is_noise(row)


def test_perl_helper_is_noise():
    row = _row("tetragon", "exec /usr/bin/lwp-request")
    assert events.classify(row)["key"] == "perl-script"


def test_rkhunter_shared_memory_is_explained_not_noise():
    row = _row("rkhunter", "Warning: The following suspicious (large) shared "
                           "memory segment(s) were found")
    hit = events.classify(row)
    assert hit["bucket"] == events.EXPLAINED
    assert not events.is_noise(row)


def test_rkhunter_properties_warning_names_the_fix():
    row = _row("rkhunter", "Warning: The file properties have changed")
    hit = events.classify(row)
    assert hit["bucket"] == events.EXPLAINED
    assert "propupd" in hit["why"]


def test_unattributed_deny_is_explained():
    row = _row("appfw", "appfw <unknown> → 208.82.238.17:443 deny "
                        "[answered: deny]", sev="MEDIUM")
    assert events.bucket_of(row) == events.EXPLAINED


def test_plain_allow_has_no_reading():
    row = _row("appfw", "appfw brave → 66.85.137.107:443 allow", sev="MEDIUM")
    assert events.classify(row) is None
    assert events.bucket_of(row) == events.REAL


def test_repeated_test_runs_collapse_to_one_group():
    rows = [_row("responderd", "quarantine: /tmp/pytest-of-grey/pytest-33/"
                               "test_yara_hit_test0/sample.bin "
                               "(sha256:275a021b) tmpfs:Eicar-Test-Signature",
                 ts="2026-10-29T09:24:18+00:00"),
            _row("responderd", "quarantine: /tmp/pytest-of-grey/pytest-34/"
                               "test_yara_hit_test0/sample.bin "
                               "(sha256:275a021b) tmpfs:Eicar-Test-Signature",
                 ts="2026-10-29T09:28:46+00:00")]
    groups = events.group(rows)
    assert len(groups) == 1
    assert groups[0]["count"] == 2
    assert groups[0]["first"] < groups[0]["last"]
    assert len(events.unique_rows(rows)) == 1


def test_groups_are_newest_first():
    rows = [_row("appfw", "appfw a → 1.2.3.4:443 allow", sev="MEDIUM",
                 ts="2026-10-29T09:00:00+00:00"),
            _row("appfw", "appfw b → 1.2.3.5:443 allow", sev="MEDIUM",
                 ts="2026-10-29T11:00:00+00:00")]
    assert events.group(rows)[0]["row"]["text"].startswith("appfw b")


def test_count_noise_only_counts_serious_rows_by_default():
    rows = [_row("responderd", "quarantine: /tmp/pytest-of-grey/pytest-1/x",
                 sev="HIGH"),
            _row("responderd", "quarantine: /tmp/pytest-of-grey/pytest-1/x",
                 sev="LOW")]
    assert events.count_noise(rows) == 1
    assert events.count_noise(rows, severity=None) == 2


def test_note_is_empty_for_an_unexplained_row():
    assert events.note(_row("appfw", "appfw x → 1.2.3.4:443 allow",
                            sev="MEDIUM")) == ""
    assert "test suite" in events.note(
        _row("responderd", "quarantine: /tmp/pytest-of-grey/pytest-1/x"))


def test_advice_does_not_rank_a_test_fixture():
    from assistant import advice
    pack = {"tools": [], "recent": [], "history": [
        _row("responderd", "quarantine: /tmp/pytest-of-grey/pytest-9/"
                           "test_yara_hit_test0/sample.bin Eicar-Test-Signature",
             ts="2026-10-29T23:00:00+00:00")]}
    assert advice.needs_attention(pack) == []
    text = advice.advise_priorities(pack)
    assert "Nothing needs a decision" in text
    assert "test fixtures" in text


def test_answer_event_marks_the_fixture_and_counts_repeats():
    from assistant.templates import answer_event
    rows = [_row("responderd", "quarantine: /tmp/pytest-of-grey/pytest-3/"
                               "test_yara_hit_test0/sample.bin "
                               "Eicar-Test-Signature", ts="2026-10-29T09:00:00+00:00"),
            _row("responderd", "quarantine: /tmp/pytest-of-grey/pytest-4/"
                               "test_yara_hit_test0/sample.bin "
                               "Eicar-Test-Signature", ts="2026-10-29T09:30:00+00:00")]
    text = answer_event({"recent": rows})
    assert "known benign" in text
    assert "×2" in text
