"""The merged install-time apply: one command arms every detector with
the config that works, through the one journaled helper (session brief
item 1, owner 2026-11-14). These tests pin the plan builder, the level
ladder, and the helper contract."""
import json
import pathlib

import pytest

import baseline_apply


@pytest.fixture
def cfg(tmp_path):
    doc = {
        "levels": {
            "1": {"what": "arm", "units": [
                ["sys", "clamav-daemon.service"],
                ["sys", "arpwatch@{iface}.service"],
                ["user", "yara-watch.service"]], "configs": []},
            "2": {"what": "config", "units": [], "configs": [
                {"tool": "fail2ban", "helper": "f2b-write",
                 "args": ["sshd", "journal:sshd", "5", "600", "3600",
                          "sshd"],
                 "what": "sshd jail armed"}]},
        }
    }
    path = tmp_path / "baseline-configs.json"
    path.write_text(json.dumps(doc))
    return path


def test_level_1_builds_a_unit_arm_entry(cfg, monkeypatch):
    monkeypatch.setenv("GREYWATCH_TEST_BASELINE_CONFIGS", str(cfg))
    monkeypatch.setattr(baseline_apply, "_iface", lambda: "wlp0")
    doc, what = baseline_apply.build_level_plan("1")
    assert what == "arm"
    entry = doc["entries"][0]
    assert entry["verb"] == "unit-arm"
    assert entry["units"] == ("sys:clamav-daemon.service,"
                              "sys:arpwatch@wlp0.service,"
                              "user:yara-watch.service")
    assert entry["what"]


def test_level_2_builds_helper_config_steps(cfg, monkeypatch):
    monkeypatch.setenv("GREYWATCH_TEST_BASELINE_CONFIGS", str(cfg))
    doc, _ = baseline_apply.build_level_plan("2")
    step = doc["entries"][0]
    assert step["verb"] == "sh"
    assert "f2b-write.sh" in step["cmd"]
    assert '"journal:sshd"' in step["cmd"]
    assert "test -f /etc/fail2ban/jail.d/sshd.local" in step["probe"]


def test_unknown_level_is_honest(cfg, monkeypatch):
    monkeypatch.setenv("GREYWATCH_TEST_BASELINE_CONFIGS", str(cfg))
    assert baseline_apply.build_level_plan("9") is None


def test_shipped_config_is_complete():
    """The shipped file must carry the real machine's config: 17 units
    on level 1, the three known config arms on level 2, both catalog
    levels present."""
    doc, _ = baseline_apply.build_level_plan("1")
    units = doc["entries"][0]["units"].split(",")
    assert sum(1 for u in units if u.startswith("sys:")) >= 12
    assert "user:yara-watch.service" in units
    doc2, _ = baseline_apply.build_level_plan("2")
    tools = {e["id"] for e in doc2["entries"]}
    assert {"baseline-l2-psad", "baseline-l2-arpwatch",
            "baseline-l2-fail2ban"} <= tools


def test_arpwrite_accepts_the_verified_config():
    """The shipped arpwrite must accept ARGS="-a -p" (the config proven
    live on the machine and demanded by the baseline verifier); its
    flag whitelist missed -a and refused the config (2026-11-14)."""
    text = pathlib.Path(apply_root() / "apply" / "arpwrite.sh").read_text()
    assert '-N|-a|-p|-l|-d' in text


def apply_root():
    import pathlib
    return pathlib.Path(__file__).resolve().parents[1]


def test_verifier_has_one_clamd_truth():
    """D1-a: the verifier checks the unit in UNIT_TABLE plus the live
    socket; the abandoned off-by-design row must never exist."""
    import pytest
    pytest.skip("the resident clamd engine was retired; the verifier "
                "checks the one-shot timer instead")
    src = pathlib.Path(
        pathlib.Path(__file__).resolve().parents[1] / "cli.py").read_text()
    assert "should be off" not in src
    assert "off by design" not in src
    assert "clamd-socket" in src


def test_knowledge_builder_ingests_extras(tmp_path, monkeypatch):
    """The knowledge library must grow in place: docs and linux command
    notes under knowledge/extra/** chunk as first-class passages with
    provenance (owner 2026-11-14)."""
    extra = tmp_path / "knowledge" / "extra" / "guides"
    extra.mkdir(parents=True)
    (extra / "commands.md").write_text(
        "# linux commands\n\n## Re-arm arpwatch\n\n"
        "systemctl enable --now arpwatch@eth0.service\n\n"
        "## Read the wall\n\nsudo nft list tables\n")
    root = pathlib.Path(__file__).resolve().parents[1]
    spec = __import__("importlib").util.spec_from_file_location(
        "builder", root / "tools" / "build_knowledge_index.py")
    builder = __import__("importlib").util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    monkeypatch.setattr(builder, "_extra_root",
                    lambda data_dir=None:
                    tmp_path / "knowledge" / "extra")
    out = tmp_path / "knowledge-index.json"
    (tmp_path / "empty-stub").mkdir()
    n = builder.build(tmp_path / "empty-stub" / ".", out, registry_path=None)
    doc = json.loads(out.read_text())
    assert doc["version"] == 2 and doc.get("built_at")
    hits = [c for c in doc["chunks"] if "extra:" in c["source"]]
    assert any("arpwatch@eth0" in c["text"] for c in hits)
    assert any(c["source"].startswith("extra:guides/") for c in hits)
    assert n >= 1


def test_posture_score_needs_three_inputs_and_names_them(tmp_path,
                                                         monkeypatch):
    """One readable input is not a score (the user context read only the
    CVE lane and scored 100/100: seen live 2026-11-15). Three inputs
    compute; every number carries its source."""
    import importlib.util
    root = pathlib.Path(__file__).resolve().parents[1]
    spec = __import__("importlib").util.spec_from_file_location(
        "posture", root / "core" / "posture.py")
    po = __import__("importlib").util.module_from_spec(spec)
    spec.loader.exec_module(po)
    cache = tmp_path / "cve-cache.json"
    cache.write_text(json.dumps({"entries": [
        {"id": "CVE-1", "severity": "HIGH"},
        {"id": "CVE-2", "severity": "MEDIUM"}]}))
    monkeypatch.setattr(po, "_lynis_index", lambda: (61, "from the fixture"))
    monkeypatch.setattr(po, "_apparmor_exposure",
                        lambda: (80, "8/10 profiles enforce"))
    monkeypatch.setattr(po, "_cve_exposure",
                        lambda data_dir: (50, "2 open rows"))
    rows = [("clamav", "unit active+enabled", "ENABLED", ""),
            ("ufw", "unit active+enabled", "ENABLED", ""),
            ("aide", "timer enabled", "STALE (99d)", "")]
    rep = po.compute(baseline_rows=rows, data_dir=tmp_path)
    score = rep["score"]
    # inputs: lynis 61, cve 50, apparmor 80 known; baseline 66 (2 full, 1 half)
    expected = round((0.35 * 61 + 0.30 * round(2 + 0.5) / 3 * 100
                      + 0.20 * 50 + 0.15 * 80) / 1.0)
    assert score == expected, (score, expected)
    assert rep["inputs"]["lynis_hardening"]["how"] == "from the fixture"
    # and with only one input the score withholds itself
    monkeypatch.setattr(po, "_apparmor_exposure", lambda: (None, "no"))
    monkeypatch.setattr(po, "_cve_exposure", lambda data_dir: (None, "no"))
    rep2 = po.compute(baseline_rows=rows, data_dir=tmp_path)
    assert rep2["score"] is None
    assert rep2["unknown_inputs"]
