"""tests/test_harden_shell.py — offline end-to-end battery for apply/harden.sh.

Real bash runs the helper (subprocess), but EVERY privileged tool is a
PATH shim in a temp dir (systemctl, sysctl, apt-get, nft) and the helper's
runtime state is redirected per test: GREYWATCH_DATA_DIR points at the
temp data dir and GREYWATCH_TEST_SYSCTL_CONF at a temp conf. No test ever
touches pkexec, sudo, a live systemd, /etc, or the repo's own data/.
"""
import json
import os
import pathlib
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
HELPER = REPO / "apply" / "harden.sh"

SYSTEMCTL_SHIM = """\
#!/bin/bash
# systemctl shim: every call logged; enable/active state is two flag files.
D="$GW_SHIM_STATE"
printf '%s\\n' "$*" >> "$D/systemctl.log"
first="$1"; case "$1" in --) first="$2" ;; esac
case "$first" in
    is-enabled)  if [ -f "$D/unit-enabled" ]; then echo enabled
                 else echo not-found; fi ;;
    is-active)   if [ -f "$D/unit-active" ]; then echo active
                 else echo inactive; fi ;;
    disable)     rm -f "$D/unit-enabled" "$D/unit-active"
                 : > "$D/disabled.flag" ;;
    enable)      : > "$D/unit-enabled" ;;
    start)       : > "$D/unit-active" ;;
    stop)        rm -f "$D/unit-active" ;;
    *)           : ;;
esac
exit 0
"""

SYSCTL_SHIM = """\
#!/bin/bash
printf '%s\\n' "$*" >> "$GW_SHIM_STATE/sysctl.log"
exit 0
"""

APTGET_SHIM = """\
#!/bin/bash
printf '%s\\n' "$*" >> "$GW_SHIM_STATE/apt-get.log"
exit 0
"""

NFT_SHIM = """\
#!/bin/bash
printf '%s\\n' "$*" >> "$GW_SHIM_STATE/nft.log"
exit 0
"""

SHIMS = {"systemctl": SYSTEMCTL_SHIM, "sysctl": SYSCTL_SHIM,
         "apt-get": APTGET_SHIM, "nft": NFT_SHIM}


class Harness:
    """One temp fake environment + a run() for the helper."""

    def __init__(self, tmp_path):
        self.tmp = pathlib.Path(tmp_path)
        self.shim_bin = self.tmp / "shim" / "bin"
        self.state = self.tmp / "shim" / "state"
        self.shim_bin.mkdir(parents=True)
        self.state.mkdir()
        self.conf_dir = self.tmp / "conf"
        self.conf_dir.mkdir()
        for name, body in SHIMS.items():
            p = self.shim_bin / name
            p.write_text(body)
            p.chmod(0o755)
        self.data = self.tmp / "data"
        self.data.mkdir()
        self.conf = self.conf_dir / "99-greywatch-hardening.conf"
        self.journal = self.data / "hardening-journal.jsonl"
        self.env = os.environ.copy()
        self.env.pop("GREYWATCH_HELPER_CMD", None)
        self.env.update(
            PATH=f"{self.shim_bin}:{self.env['PATH']}",
            GW_SHIM_STATE=str(self.state),
            GREYWATCH_DATA_DIR=str(self.data),
            GREYWATCH_TEST_SYSCTL_CONF=str(self.conf),
        )
        (self.state / "unit-enabled").touch()    # fake unit: enabled+active
        (self.state / "unit-active").touch()

    def run(self, args):
        return subprocess.run(
            ["bash", str(HELPER), *args], capture_output=True, text=True,
            env=self.env, cwd=str(self.tmp), timeout=60)

    def planfile(self, entries):
        p = self.tmp / "plan.json"
        p.write_text(json.dumps({"entries": entries}) + "\n",
                     encoding="utf-8")
        return str(p)


@pytest.fixture()
def h(tmp_path):
    return Harness(tmp_path)


def T(h, rel):
    return str(h.tmp / rel)


def test_apply_runs_all_verbs_and_writes_the_journal(h):
    plan = h.planfile([
        {"id": "step-shell", "verb": "sh",
         "cmd": f"echo hi > {T(h, 'sh-out')}",
         "probe": f"test -f {T(h, 'sh-out')}"},
        {"id": "set-knob", "verb": "sysctl-set", "key": "gw.test.knob",
         "value": "1",
         "probe": f"grep -q 'gw.test.knob = 1' {h.conf}"},
        {"id": "stop-service", "verb": "service-off",
         "unit": "fake.service",
         "probe": f"test -f {T(h, 'shim/state/disabled.flag')}"},
    ])
    p = h.run(["apply", plan])
    for cid in ("step-shell", "set-knob", "stop-service"):
        assert f"APPLY {cid} 0" in p.stdout, p.stdout + p.stderr
        assert f"VERBIFY {cid} 0" in p.stdout, p.stdout + p.stderr
    assert p.returncode == 0, p.stdout + p.stderr
    # the journal exists, is JSONL, one record per mutated id, each with
    # before-values and the plan entry for re-probe
    lines = h.journal.read_text(encoding="utf-8").splitlines()
    recs = [json.loads(x) for x in lines]
    ids = [r["id"] for r in recs]
    # step-shell has nothing journalable (no files were backed up); the
    # mutating two are journaled BEFORE their mutation
    assert ids == ["set-knob", "stop-service"], ids
    for r in recs:
        assert r["ts"] and r["before"] and r["plan"][0]["id"] == r["id"]
    by_id = {r["id"]: r for r in recs}
    assert by_id["set-knob"]["before"][str(h.conf)] == {"absent": True}
    st = by_id["stop-service"]["before"]["fake.service"]
    assert st["was-enabled"] == "enabled" and st["was-active"] == "active"
    # effects landed
    assert "gw.test.knob = 1" in h.conf.read_text(encoding="utf-8")
    assert (h.state / "disabled.flag").exists()
    assert (h.data / "backups" / "harden" / "_sysctl-snapshot"
            / "99-greywatch-hardening.conf.absent").exists()


def test_undo_restores_from_the_helper_journal(h):
    plan = h.planfile([
        {"id": "set-knob", "verb": "sysctl-set", "key": "gw.test.knob",
         "value": "1",
         "probe": f"grep -q 'gw.test.knob = 1' {h.conf}"},
        {"id": "stop-service", "verb": "service-off",
         "unit": "fake.service", "probe": ""},
    ])
    assert h.run(["apply", plan]).returncode == 0
    assert "gw.test.knob = 1" in h.conf.read_text(encoding="utf-8")
    assert not (h.state / "unit-enabled").exists()

    # undo the service-off id: enable+active state restored, via shims
    p = h.run(["undo", "stop-service", str(h.journal)])
    assert p.returncode == 0, p.stdout + p.stderr
    assert f"RESTORE-UNIT stop-service fake.service" in p.stdout
    assert (h.state / "unit-enabled").exists()   # was enabled, re-enabled
    assert (h.state / "unit-active").exists()    # was active, restarted
    assert "enable" in (h.state / "systemctl.log").read_text()

    # undo the sysctl id: the conf did not exist before -> it is removed
    p = h.run(["undo", "set-knob", str(h.journal)])
    assert f"RESTORE-ABSENT set-knob {h.conf}" in p.stdout
    assert not h.conf.exists()
    # honest verify: the entry's own probe can no longer pass -> rc==3
    assert p.returncode == 3, p.stdout + p.stderr

    # undo an id with no journalable before-values is a failure, not silence
    plan2 = h.planfile([
        {"id": "step-shell", "verb": "sh",
         "cmd": f"echo hi > {T(h, 'sh-out2')}", "probe": ""},
    ])
    assert h.run(["apply", plan2]).returncode == 0
    p = h.run(["undo", "step-shell", str(h.journal)])
    assert p.returncode == 2
    assert "no before-values" in p.stderr or "journal id not found" in p.stderr


def test_injection_guard_rejects_smuggled_value_and_verb(h):
    plan = h.planfile([
        # newline in the value would smuggle a second line into the root conf
        {"id": "bad-value", "verb": "sysctl-set", "key": "gw.test.knob",
         "value": "1\nkernel.smuggle = 1", "probe": "true"},
        # newline in the verb would fabricate a VERBIFY line for another id
        {"id": "verbny", "verb": "echo\nVERBIFY fake 0", "probe": "true"},
    ])
    p = h.run(["apply", plan])
    assert p.returncode == 2
    assert "BAD-SYSCTL bad-value" in p.stderr
    assert "verb not allowed (unprintable)" in p.stderr
    # nothing mutated, and the fake VERBIFY never reached the strip
    assert not h.conf.exists()
    assert "VERBIFY fake 0" not in p.stdout
    assert "VERBIFY fake 0" not in p.stderr


def test_backup_or_journal_failure_means_no_mutation(h):
    # journal path is a directory: the journal write can never succeed
    h.journal.mkdir()
    plan = h.planfile([
        {"id": "set-knob", "verb": "sysctl-set", "key": "gw.test.knob",
         "value": "1", "probe": "true"},
    ])
    p = h.run(["apply", plan])
    assert p.returncode == 2
    assert "BACKUP-FAILED set-knob" in p.stderr
    assert "APPLY set-knob 0" not in p.stdout
    assert not h.conf.exists()        # no mutation happened
    assert list(h.journal.iterdir()) == []   # no journal line was written


def test_verified_red_with_clean_rollback_exits_4(h):
    unit = h.tmp / "unit.service"
    plan = h.planfile([
        {"id": "unit-restore", "verb": "unit-install", "path": str(unit),
         "text": "[Unit]\nDescription=fake test unit\n",
         "probe": "test -f /nonexistent/no-such-probe-file"},
    ])
    p = h.run(["apply", plan])
    assert "APPLY unit-restore 0" in p.stdout
    assert "VERBIFY unit-restore" in p.stdout
    assert "ROLLBACK unit-restore" in p.stdout, p.stdout + p.stderr
    assert p.returncode == 4          # clean rollback: 4, not 0
    assert not unit.exists()          # backup .absent -> file removed again
    assert "BAD" not in p.stderr


def test_plan_mode_echoes_and_validates(h):
    plan = h.planfile([
        {"id": "only-check", "verb": "sh", "cmd": "true", "probe": ""},
    ])
    p = h.run(["plan", plan])
    assert p.returncode == 0
    assert json.loads(p.stdout)["entries"][0]["id"] == "only-check"
    p = h.run(["plan", str(h.tmp / "nope.json")])
    assert p.returncode == 2

# ---- W5: verb aliases, verify verb, changeset handoff, per-pass dirs ----

FRAGMENT_SYSCTL = {
    "entries": [{
        "id": "set-knob", "verb": "sysctl-set", "key": "gw.test.knob",
        "value": "1",
        "probe": "grep -q 'gw.test.knob = 1' {CONF}",
    }],
}


def _changeset(h, jid, journal, changes):
    cs = {"version": 1, "journal_id": jid, "changes": changes}
    p = h.tmp / "changeset.json"
    p.write_text(json.dumps(cs) + "\n", encoding="utf-8")
    return str(p)


def test_aliases_behave_like_the_bare_verbs(h):
    plan = h.planfile([
        {"id": "set-knob", "verb": "sysctl-set", "key": "gw.test.knob",
         "value": "1",
         "probe": f"grep -q 'gw.test.knob = 1' {h.conf}"},
    ])
    p = h.run(["--apply", plan])
    assert p.returncode == 0, p.stdout + p.stderr
    assert "VERBIFY set-knob 0" in p.stdout
    assert "gw.test.knob = 1" in h.conf.read_text(encoding="utf-8")
    assert not (h.data / "harden" / "journal").exists()  # plan-json keeps
    #                                                     the plain layout

    q = h.run(["--undo", "set-knob", str(h.journal)])
    assert q.returncode == 3
    assert f"RESTORE-ABSENT set-knob {h.conf}" in q.stdout

    r = h.run(["--verify", "set-knob", str(h.journal)])
    assert r.returncode == 3          # probe (fixed-state) honestly fails
    assert "VERBIFY set-knob" in r.stdout

    u = h.run(["--verify", "no-such-id", str(h.journal)])
    assert u.returncode == 2          # unknown journal id, named
    assert "journal id not found" in u.stderr

    x = h.run(["frobnicate"])
    assert x.returncode == 2
    assert "unknown verb: frobnicate" in x.stderr


def test_verify_reprints_the_apply_probes_green(h):
    plan = h.planfile([
        {"id": "set-knob", "verb": "sysctl-set", "key": "gw.test.knob",
         "value": "1", "probe": "true"},
    ])
    assert h.run(["apply", plan]).returncode == 0
    p = h.run(["verify", "set-knob", str(h.journal)])
    assert p.returncode == 0, p.stdout + p.stderr
    assert "VERBIFY set-knob 0" in p.stdout
    assert "RESTORE" not in p.stdout   # verify never restores


def test_changeset_apply_writes_the_per_pass_journal_dir(h):
    jid = "20261025-090000"
    h.data.joinpath("harden", "journal", jid).mkdir(parents=True)
    frag = h.data / "harden" / "journal" / jid / "set-knob.json"
    frag.write_text(json.dumps(
        {"entries": [{
            "id": "set-knob", "verb": "sysctl-set", "key": "gw.test.knob",
            "value": "1",
            "probe": f"grep -q 'gw.test.knob = 1' {h.conf}",
        }]}) + "\n", encoding="utf-8")
    cs = _changeset(h, jid, h.journal, [
        {"control_id": "set-knob", "action": "apply",
         "backup_path": str(frag)}])
    p = h.run(["--apply", cs])
    assert p.returncode == 0, p.stdout + p.stderr
    assert "VERBIFY set-knob 0" in p.stdout
    assert "gw.test.knob = 1" in h.conf.read_text(encoding="utf-8")
    pass_dir = h.data / "harden" / "journal" / jid
    assert (pass_dir / "journal.jsonl").exists()
    assert (pass_dir / "backups" / "_sysctl-snapshot"
            / "99-greywatch-hardening.conf.absent").exists()
    recs = [json.loads(x) for x in
            (pass_dir / "journal.jsonl").read_text(encoding="utf-8")
            .splitlines()]
    assert recs[0]["id"] == "set-knob" and recs[0]["before"]


def test_changeset_verify_and_rollback_directives(h):
    jid = "20261025-091000"
    h.data.joinpath("harden", "journal", jid).mkdir(parents=True)
    frag = h.data / "harden" / "journal" / jid / "stop-service.json"
    frag.write_text(json.dumps(
        {"entries": [{
            "id": "stop-service", "verb": "service-off",
            "unit": "fake.service",
            "probe": f"test -f {T(h, 'shim/state/disabled.flag')}",
        }]}) + "\n", encoding="utf-8")
    # one pass: apply the control, then a LATER pass's rollback directive
    # served here as its own document (duplicates are refused, so apply
    # and rollback for one id are always separate passes)
    cs = _changeset(h, jid, h.journal, [
        {"control_id": "stop-service", "action": "apply",
         "backup_path": str(frag)}])
    assert h.run(["--apply", cs]).returncode == 0
    assert (h.state / "disabled.flag").exists()

    pass_journal = str(h.data / "harden" / "journal" / jid / "journal.jsonl")
    ver = h.run(["verify", "stop-service", pass_journal])
    assert ver.returncode == 0
    assert "VERBIFY stop-service 0" in ver.stdout

    # the rollback directive's fragment sits in the PASS DIR it undoes
    # (dirname(backup_path)/journal.jsonl names the target journal)
    pass_dir = h.data / "harden" / "journal" / jid
    rbfrag = pass_dir / "stop-service.json"
    rbfrag.write_text(frag.read_text(encoding="utf-8"), encoding="utf-8")
    cs2 = _changeset(h, "20261025-091001", h.journal, [
        {"control_id": "stop-service", "action": "rollback",
         "backup_path": str(rbfrag)}])
    p = h.run(["--apply", cs2])
    assert p.returncode == 0, p.stdout + p.stderr
    assert "CHANGES-ROLLBACK stop-service" in p.stdout
    assert (h.state / "unit-enabled").exists()   # re-enabled by the undo
    # the per-pass dir for the rollback pass exists too (it carries no
    # journal line: nothing was mutated by that pass)
    assert (h.data / "harden" / "journal" / "20261025-091001"
            / "backups").exists()


def test_changeset_verify_directive_probes_without_mutating(h):
    jid = "20261025-092000"
    h.data.joinpath("harden", "journal", jid).mkdir(parents=True)
    frag = h.data / "harden" / "journal" / jid / "stop-service.json"
    frag.write_text(json.dumps(
        {"entries": [{
            "id": "stop-service", "verb": "service-off",
            "unit": "fake.service", "probe": "false",
        }]}) + "\n", encoding="utf-8")
    cs = _changeset(h, jid, h.journal, [
        {"control_id": "stop-service", "action": "verify",
         "backup_path": str(frag)}])
    p = h.run(["--apply", cs])
    # the no-op sh fix verified RED: sh has nothing backed up, so the pass
    # cannot claim a rollback — ROLLBACK-SKIP, rc 4 per the ladder. Honest.
    assert p.returncode == 4
    assert "VERBIFY stop-service 1" in p.stdout
    assert "ROLLBACK-SKIP stop-service" in p.stderr
    assert not (h.state / "disabled.flag").exists()   # nothing mutated


def test_changeset_duplicate_control_id_refused(h):
    jid = "20261025-093000"
    h.data.joinpath("harden", "journal", jid).mkdir(parents=True)
    frag = h.data / "harden" / "journal" / jid / "set-knob.json"
    frag.write_text(json.dumps(
        {"entries": [{"id": "set-knob", "verb": "sysctl-set",
                      "key": "gw.test.knob", "value": "1",
                      "probe": "true"}]}) + "\n", encoding="utf-8")
    cs = _changeset(h, jid, h.journal, [
        {"control_id": "set-knob", "action": "apply",
         "backup_path": str(frag)},
        {"control_id": "set-knob", "action": "rollback",
         "backup_path": str(frag)},
    ])
    p = h.run(["--apply", cs])
    assert p.returncode == 2
    assert "CHANGES-DUP-ID set-knob" in p.stderr     # named, decided (W3)
    pd = h.data / "harden" / "journal" / jid
    assert not (pd / "journal.jsonl").exists()   # nothing ran
    assert not (pd / "backups").exists()
    assert not h.conf.exists()                        # nothing mutated


def test_changeset_refusals_are_named_and_inert(h):
    jid = "20261025-094000"
    h.data.joinpath("harden", "journal", jid).mkdir(parents=True)
    frag = h.data / "harden" / "journal" / jid / "set-knob.json"
    frag.write_text(json.dumps({"entries": []}) + "\n", encoding="utf-8")
    cases = [
        # version
        ({"version": 2, "journal_id": jid, "changes": [
             {"control_id": "set-knob", "action": "apply",
              "backup_path": str(frag)}]},
         "CHANGES-BAD-VERSION"),
        # journal id shape
        ({"version": 1, "journal_id": "oops", "changes": [
             {"control_id": "set-knob", "action": "apply",
              "backup_path": str(frag)}]},
         "CHANGES-BAD-JOURNAL-ID"),
        # unknown action -> never executed as anything
        ({"version": 1, "journal_id": jid, "changes": [
             {"control_id": "set-knob", "action": "purge",
              "backup_path": str(frag)}]},
         "CHANGES-BAD-ACTION set-knob"),
        # metacharacter backup path
        ({"version": 1, "journal_id": jid, "changes": [
             {"control_id": "set-knob", "action": "apply",
              "backup_path": "/tmp/x;y.json"}]},
         "CHANGES-BACKUP-PATH set-knob"),
        # '..' traversal anywhere in the fragment path
        ({"version": 1, "journal_id": jid, "changes": [
             {"control_id": "set-knob", "action": "apply",
              "backup_path": str(h.data / "harden" / "journal" / ".."
                                 / jid / "set-knob.json")}]},
         "CHANGES-BACKUP-PATH-TRAVERSAL set-knob"),
        # well-formed fragment layout, but OUT of this pass's dir
        ({"version": 1, "journal_id": jid, "changes": [
             {"control_id": "set-knob", "action": "apply",
              "backup_path": str(h.data / "harden" / "journal"
                                 / "19991231-235959" / "set-knob.json")}]},
         "CHANGES-BACKUP-PATH-SCOPE set-knob"),
        # rollback row outside the per-pass layout
        ({"version": 1, "journal_id": jid, "changes": [
             {"control_id": "set-knob", "action": "rollback",
              "backup_path": "/tmp/outside/harden/journal/"
                             "19991231-235959/set-knob.json"}]},
         "CHANGES-ROLLBACK-SCOPE set-knob"),
    ]
    for body, needle in cases:
        p = h.tmp / "cs-bad.json"
        p.write_text(json.dumps(body) + "\n", encoding="utf-8")
        r = h.run(["--apply", str(p)])
        assert r.returncode == 2, needle
        assert needle in r.stderr, (needle, r.stdout + r.stderr)
        assert not h.conf.exists()
        assert not (h.data / "harden" / "journal" / jid
                    / "journal.jsonl").exists()
        assert not (h.data / "harden" / "journal" / jid / "backups").exists()


def test_apply_reports_empty_and_foreign_documents(h):
    # a dict that is neither a plan nor a changeset: named refusal
    junk = h.tmp / "junk.json"
    junk.write_text('{"foo": 1}\n', encoding="utf-8")
    p = h.run(["apply", str(junk)])
    assert p.returncode == 2
    assert "CHANGES-SHAPE" in p.stderr, p.stdout + p.stderr
    assert not h.conf.exists()

    # a pass with zero changes (empty entries list): refuses, never 0
    empty = h.planfile([])
    p = h.run(["apply", empty])
    assert p.returncode == 2
    assert "CHANGES-SHAPE" in p.stderr, p.stdout + p.stderr
    assert not h.conf.exists()


def test_uppercase_verb_is_named_not_mislabeled(h):
    p = h.run(["APPLY"])
    assert p.returncode == 2
    assert "unknown verb: APPLY (not in the allowlist)" in p.stderr
    assert "(unprintable)" not in p.stderr


def test_alias_arity_still_usage(h):
    plan = h.planfile([{"id": "x", "verb": "sh", "cmd": "true"}])
    p = h.run(["--apply", plan, "extra"])
    assert p.returncode == 64          # arity malformation keeps usage()
    p = h.run(["--verify", "only-one-arg"])
    assert p.returncode == 64


def test_changeset_python_handoff_round_trip(h):
    """W5 round 1, I-1: build() -> write_document() -> helper apply must
    succeed with build()'s default backup_path (the per-pass convention),
    and the pass journal must land in data/harden/journal/<journal_id>/."""
    from wizard import changeset as cs
    jid = "20261025-101010"
    cards = [{"control_id": "set-knob", "action": "apply"}]
    cs_path = h.tmp / "handoff.json"
    assert cs.write_document(cs.build(jid, cards),
                             [{"id": "set-knob"}], cs_path) == []
    # the fragment in the convention slot carries the real entries
    frag = h.data / "harden" / "journal" / jid / "set-knob.json"
    frag.parent.mkdir(parents=True)
    frag.write_text(json.dumps(
        {"entries": [{
            "id": "set-knob", "verb": "sysctl-set", "key": "gw.test.knob",
            "value": "1",
            "probe": f"grep -q 'gw.test.knob = 1' {h.conf}",
        }]}) + "\n", encoding="utf-8")
    p = h.run(["--apply", cs_path])
    assert p.returncode == 0, p.stdout + p.stderr
    assert "VERBIFY set-knob 0" in p.stdout
    pass_journal = h.data / "harden" / "journal" / jid / "journal.jsonl"
    recs = [json.loads(x) for x in
            pass_journal.read_text(encoding="utf-8").splitlines()]
    assert recs[0]["id"] == "set-knob"


def test_symlinked_fragment_outside_pass_dir_refused(h):
    """W5 round 2: a symlink INSIDE the pass dir pointing at a fragment
    outside must be refused by realpath-scope — no execution, no journal."""
    from wizard import changeset as cs
    outside = h.tmp / "OUTSIDE.json"
    outside.write_text(json.dumps(
        {"entries": [{"id": "set-knob", "verb": "sysctl-set",
                      "key": "gw.test.knob", "value": "1",
                      "probe": "true"}]}) + "\n", encoding="utf-8")
    jid = "20261025-111000"
    pdir = h.data / "harden" / "journal" / jid
    pdir.mkdir(parents=True)
    (pdir / "set-knob.json").symlink_to(outside)
    doc = cs.build(jid, [{"control_id": "set-knob"}])
    cs_path = h.tmp / "handoff-symlink.json"
    assert cs.write_document(doc, [{"id": "set-knob"}], cs_path) == []
    p = h.run(["--apply", str(cs_path)])
    assert p.returncode == 2
    assert "CHANGES-BACKUP-PATH-SCOPE set-knob" in p.stderr, \
        p.stdout + p.stderr
    assert not h.conf.exists()                        # nothing executed
    assert not (pdir / "journal.jsonl").exists()      # no journal written
    assert outside.stat().st_size > 0                 # outside file untouched
    # build()'s default backup_path is the RELATIVE canonical form, which
    # validate() cannot realpath without the data dir (the helper's scope
    # gate is authoritative there; the helper refused above) — the
    # python-side symlink mirror covers the ABSOLUTE form:
    abs_doc = cs.build(jid, [{"control_id": "set-knob",
                              "backup_path": str(pdir / "set-knob.json")}])
    errs = cs.validate(abs_doc, [{"id": "set-knob"}])
    assert any("resolves (symlink) outside" in e for e in errs), errs


def test_symlinked_rollback_journal_refused(h):
    """The undo journal itself is symlink-checked: a pass-dir journal
    pointing at an outside file is refused before undo reads it as root."""
    from wizard import changeset as cs
    jid = "20261025-112000"
    pdir = h.data / "harden" / "journal" / jid
    pdir.mkdir(parents=True)
    (pdir / "set-knob.json").write_text(json.dumps({"entries": []}) + "\n",
                                        encoding="utf-8")
    outj = h.tmp / "outside-journal.jsonl"
    outj.write_text('{"id":"set-knob","before":{},"plan":[]}\n',
                    encoding="utf-8")
    (pdir / "journal.jsonl").symlink_to(outj)
    doc = {"version": 1, "journal_id": "20261025-112001", "changes": [
        {"control_id": "set-knob", "action": "rollback",
         "backup_path": str(pdir / "set-knob.json")}]}
    cs_path = h.tmp / "handoff-rb-symlink.json"
    p = h.run(["--apply", cs_path])
    # (unwritable-by-shim changeset still parsed: write it properly)
    cs_path.write_text(json.dumps(doc) + "\n", encoding="utf-8")
    p = h.run(["--apply", str(cs_path)])
    assert p.returncode == 2
    assert "CHANGES-ROLLBACK-SCOPE set-knob" in p.stderr, \
        p.stdout + p.stderr
    assert outj.read_text(encoding="utf-8").strip() == \
        '{"id":"set-knob","before":{},"plan":[]}'    # never read+undone
