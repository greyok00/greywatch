"""Path resolution: "~" and "{GW}" in the registry must resolve to the
RIGHT directories when the ROOT daemon reads them.

Two regressions live here:
  1. "~" used Path.home(), which is /root for the root daemon — every
     ~/security-hardening log read as missing → tools falsely YELLOW.
  2. "{GW}/data/..." resolved to the CODE dir (/usr/lib/greywatch/data),
     which does not exist — the state dir is /var/lib/greywatch. The
     {STATE} token now points at the runtime state dir.
"""
import os
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_tilde_resolves_to_ui_user_home(monkeypatch):
    # simulate the root daemon: GREYWATCH_UI_USER points at a real user.
    # Use the CURRENT user (works on any host: local dev box = grey,
    # CI runner = runner) so the test is host-independent.
    import pwd
    me = pwd.getpwuid(os.getuid()).pw_name
    my_home = str(pathlib.Path.home())
    monkeypatch.setenv("GREYWATCH_UI_USER", me)
    monkeypatch.delenv("GREYWATCH_USER_HOME", raising=False)
    import importlib
    import registry
    importlib.reload(registry)
    try:
        home = registry._user_home()
        assert home == my_home, f"_user_home()={home} != {my_home}"
        # "~" paths in the registry must land in that home
        reg = registry.load_registry()
        clam = next(t for t in reg if t["name"] == "clamav")
        assert clam["logs"][0].startswith(my_home + "/"), clam["logs"]
        assert not clam["logs"][0].startswith("/root/")
    finally:
        monkeypatch.delenv("GREYWATCH_UI_USER", raising=False)
        importlib.reload(registry)


def test_state_token_resolves_to_state_dir():
    import registry
    reg = registry.load_registry()
    appfw = next(t for t in reg if t["name"] == "appfw")
    from gwpaths import data_dir
    assert appfw["logs"] == [str(data_dir() / "appfw" / "events.jsonl")]
    # must NOT point at the code dir's (nonexistent) data/
    assert "/usr/lib/greywatch/data" not in appfw["logs"][0]


def test_no_registry_path_uses_bare_gw_data():
    reg = pathlib.Path(ROOT / "registry.json").read_text(encoding="utf-8")
    assert "{GW}/data" not in reg
    assert "{STATE}/" in reg


def test_suricata_fully_removed_from_registry():
    import registry
    reg = registry.load_registry()
    names = {t["name"] for t in reg}
    assert "suricata" not in names
    assert len(reg) == 17
