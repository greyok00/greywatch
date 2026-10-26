import json
import pathlib

from events import Event, normalize_event
from registry import load_registry, tool_names

REGISTRY = load_registry()

NAMES = {"responderd", "tetragon", "yara-watch", "yara-tmp-scan", "clamav",
         "fail2ban", "ufw", "auditd", "appfw", "arpwatch", "aide",
         "apparmor", "lynis", "rkhunter", "net-watch", "cve-updater",
         "freshclam"}


def test_registry_has_all_seventeen_real_tools():
    assert len(REGISTRY) == 17
    assert {t["name"] for t in REGISTRY} == NAMES


def test_registry_labels_present():
    for t in REGISTRY:
        assert t["label"] and isinstance(t["label"], str)


def test_registry_every_tool_has_a_read_source():
    for t in REGISTRY:
        if t["name"] == "net-watch":
            continue        # synthetic: the daemon itself IS its source
        assert t.get("logs") or t.get("journal") or t.get("state_only"), \
            f"{t['name']}: no read source"


def test_registry_appfw_entry():
    af = [t for t in REGISTRY if t["name"] == "appfw"][0]
    assert af["unit"] == "greywatch.service"
    assert af["logs"] == [str(pathlib.Path.home() / "greywatch"
                                 / "data" / "appfw" / "events.jsonl")]


def test_event_roundtrip():
    e = Event(from_tool="fail2ban", severity="HIGH", text="Ban 1.2.3.4",
              ts="2026-10-22T00:00:00Z", nist_func="RESPOND",
              nist_control=["AC-7"], cves=[], interaction=None)
    assert Event.from_dict(json.loads(json.dumps(e.to_dict()))) == e


def test_event_from_dict_rejects_foreign_keys():
    try:
        Event.from_dict({"from_tool": "x", "severity": "INFO", "text": "t", "ts": "z", "bogus": 1})
    except KeyError:
        pass
    else:
        raise AssertionError("foreign key silently accepted")


def test_unknown_tool_returns_none():
    assert normalize_event("nonexistent-tool", "some line") is None


def test_tool_names_helper():
    assert "ufw" in tool_names(REGISTRY)
