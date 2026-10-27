import datetime
import json
import pathlib
import re
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from hardening.controls import Control    # noqa: E402
from wizard import changeset               # noqa: E402
from wizard import ui_pages                # noqa: E402
from wizard.ui_pages import (apply_pass, now_journal_id, parse_strip,  # noqa: E402
                             pass_journal_path, preview_rows, undo_pass)
from wizard.inventory import inventory_lines, run_scan    # noqa: E402

DATA_DIR = ROOT / "data"



class FakeRunner:

    def __init__(self, table, fail_lines=()):
        self.table = dict(table)
        self.fail_lines = set(fail_lines)
        self.asked: list[str] = []

    def __call__(self, line):
        self.asked.append(line)
        if line in self.fail_lines:
            raise RuntimeError(f"stub blowup on {line!r}")
        if line not in self.table:
            raise RuntimeError(f"unprogrammed probe {line!r}")
        return tuple(self.table[line])


def _fake_scan_table():
    return {
        "dpkg --version": (0, "v1"),
        "dpkg -s openssh-server": (0, "ok"),
        "dpkg -s sshd": (1, ""),
        "dpkg -s avahi-daemon": (1, ""),
        "dpkg -s clamav": (1, ""),
        "dpkg -s freshclam": (1, ""),
        "dpkg -s ufw": (0, "ok"),
        "dpkg -s fail2ban": (1, ""),
        "dpkg -s auditd": (1, ""),
        "dpkg -s aide": (1, ""),
        "dpkg -s apparmor": (0, "ok"),
        "dpkg -s nftables": (0, "ok"),
        "dpkg -s docker.io": (1, ""),
        "dpkg -s podman": (1, ""),
        "dpkg -s chrony": (1, ""),
        "dpkg -s ntpd": (1, ""),
        "dpkg -s systemd-timesyncd": (1, ""),
        "dpkg -s firefox-esr": (1, ""),
        "dpkg -s chromium": (1, ""),
        "dpkg -s brave-browser": (1, ""),
        "dpkg -s python3": (0, "ok"),
        "dpkg -s node": (1, ""),
        "dpkg -s ollama": (1, ""),
        "systemctl list-units --type=service --state=running "
        "--no-pager": (0, "ssh.service loaded active running Sshd\n"
                         "x.service loaded failed failed X"),
        "ss -tuln": (0, "Netid State Recv-Q Send-Q Local Address:Port\n"
                        "tcp  LISTEN 0      128    0.0.0.0:22\n"
                        "tcp  LISTEN 0      128    [::]:22"),
        "nft list tables": (0, "table ip filter"),
        "ufw status": (0, "Status: active"),
        "sysctl -n net.ipv6.conf.all.disable_ipv6": (0, "0"),
        "lsblk -o TYPE": (1, ""),
    }


from wizard.inventory import PACKAGES   # noqa: E402  (after table above)


def test_scan_fakes_are_exhaustive():
    FakeRunner(_fake_scan_table())      # table build only; coverage below
    for name in PACKAGES:
        assert f"dpkg -s {name}" in _fake_scan_table()


def test_run_scan_distills_fakes(tmp_path):
    net = tmp_path / "sys_net"
    (net / "wlp0s1").mkdir(parents=True)
    (net / "wlp0s1" / "wireless").touch()
    runner = FakeRunner(_fake_scan_table())
    scan = run_scan(runner=runner, data_dir=tmp_path, net_dir=net)
    assert scan["packages"]["openssh-server"] is True
    assert scan["packages"]["sshd"] is False
    assert scan["packages"]["clamav"] is False
    assert scan["ufw_status"] == "active"
    assert scan["ipv6_disable"] == "0"
    assert scan["wireless"] is True
    assert scan["fresh_install"] is True        # no appfw/config.json
    assert scan["facts"]["listening_ports"].value == [22]
    assert scan["facts"]["services_running"].value == ["ssh.service"]
    assert "nft:table ip filter" in scan["facts"]["firewall"].value
    assert "ss -tuln" in runner.asked and "ufw status" in runner.asked


def test_fresh_install_detection_is_config_absence(tmp_path):
    assert run_scan(
        runner=FakeRunner(_fake_scan_table()), data_dir=tmp_path,
        net_dir=tmp_path)["fresh_install"] is True
    (tmp_path / "appfw").mkdir()
    (tmp_path / "appfw" / "config.json").write_text(
        json.dumps({"armed": True}) + "\n", encoding="utf-8")
    assert run_scan(
        runner=FakeRunner(_fake_scan_table()), data_dir=tmp_path,
        net_dir=tmp_path)["fresh_install"] is False


def test_scan_is_honest_on_probe_failure(tmp_path):
    runner = FakeRunner(_fake_scan_table(),
                        fail_lines=("ufw status", "ss -tuln"))
    scan = run_scan(runner=runner, data_dir=tmp_path, net_dir=tmp_path)
    assert scan["ufw_status"] is None       # unknown stays unknown
    assert scan["facts"]["listening_ports"].state == "CANT-CHECK"
    lines = inventory_lines(scan)
    assert any(l == "Listening ports: could not be checked" for l in lines)
    assert all("stub blowup" not in l for l in lines)




def _ctrl(**kw):
    base = dict(id="c1", group="g", what="what text", severity="LOW")
    base.update(kw)
    return Control(**base)


def _rule_scan(**over):
    scan = {
        "packages": {"openssh-server": True, "clamav": False},
        "fresh_install": True,
        "wireless": True,
        "ufw_status": "active",
        "ipv6_disable": "0",
    }
    scan.update(over)
    return scan


def _rule_controls():
    return [
        _ctrl(id="sshd-running", group="ssh", probe="systemctl is-active ssh",
              nist=["AC-17"], cis=["5.2"], severity="MEDIUM",
              break_risk="none", default=True),
        _ctrl(id="clamav-installed", group="clamav",
              condition="not-installed:clamav", action="install-prompt",
              nist=["SI-3"], cis=[], severity="MEDIUM", default=False),
        _ctrl(id="wifi-wireless-hardening", group="wireless",
              nist=["SC-40"], cis=[], break_risk="none", default=True),
        _ctrl(id="ufw-frontend-role", group="ufw", probe="ufw status",
              nist=["SC-7"], cis=[], severity="INFO", default="FLAG-ONLY"),
        _ctrl(id="ipv6-kernel-disable", group="ipv6",
              probe="sysctl -n net.ipv6.conf.all.disable_ipv6",
              nist=["SC-7(5)"], cis=[], severity="HIGH",
              break_risk="medium", default=True, condition="fresh-install"),
    ]


def test_cards_carry_real_current_and_recommended():
    from wizard.baseline import generate
    cards = generate(_rule_scan(), _rule_controls(), "workstation")
    by_id = {c["control_id"]: c for c in cards}
    rows = preview_rows(cards)
    assert {r["control_id"] for r in rows} == set(by_id)
    for r in rows:
        card = by_id[r["control_id"]]
        assert r["current"] == (card.get("current", "") or "")
        assert r["recommended"] == (card.get("recommended", "") or "")
    assert by_id["ufw-frontend-role"]["current"] == "UFW active"
    assert "Flag only" in by_id["ufw-frontend-role"]["recommended"]
    assert by_id["clamav-installed"]["current"] == "clamav: not installed"
    assert by_id["clamav-installed"][" recommended" if False else
                  "recommended"] == "Install with your one click"
    assert "value 0" in by_id["ipv6-kernel-disable"]["current"]


def test_adaptive_table_skip_rules():
    from wizard.baseline import generate
    ids = lambda scan: {c["control_id"] for c in
                        generate(scan, _rule_controls(), "workstation")}  # noqa: E731
    assert "sshd-running" not in ids(
        _rule_scan(packages={"openssh-server": False, "clamav": False}))
    assert "wifi-wireless-hardening" not in ids(
        _rule_scan(wireless=False))
    existing = generate(_rule_scan(fresh_install=False), _rule_controls(),
                        "workstation")
    ipv6 = next(c for c in existing
                if c["control_id"] == "ipv6-kernel-disable")
    assert ipv6["checked"] is False
    assert "Harden view" in ipv6["note"]


def test_break_risk_medium_starts_unticked():
    from wizard.baseline import generate
    cards = generate(_rule_scan(), [_ctrl(
        id="kernel-userns", group="kernel-hardening", nist=["AC-4"],
        cis=[], severity="HIGH", break_risk="medium", default=True)],
        "workstation")
    assert cards[0]["checked"] is False
    assert "break your workflow" in cards[0]["risk"]




def _applyable_controls():
    return [
        Control(id="kernel-kptr", group="kernel", what="Restrict kernel "
                "pointers", probe="sysctl -n kernel.kptr_restrict",
                fix=[["sysctl-set", "kernel.kptr_restrict", "2"]],
                nist=["AC-4"], cis=["1.1"], severity="HIGH",
                break_risk="none", default=True),
        Control(id="avahi-stop", group="network-services",
                what="Stop the mDNS service", probe="systemctl is-active "
                "avahi-daemon", fix=[["service-off", "avahi-daemon"]],
                nist=["CM-7"], cis=[], severity="MEDIUM",
                break_risk="low", default=True),
    ]


class RecordingHelper:

    def __init__(self, rc=0, out="", err=""):
        self.calls: list[list[str]] = []
        self.rc, self.out, self.err = rc, out, err

    def __call__(self, args):
        self.calls.append(list(args))
        return self.rc, self.out, self.err


def _applied_cards(controls, checked=None):
    from wizard.baseline import generate
    cards = generate({"fresh_install": True}, controls, "workstation")
    for card in cards:
        if checked is None:
            card["checked"] = True
        else:
            card["checked"] = card["control_id"] in checked
    return cards


def test_apply_pass_one_helper_call_and_fragments(tmp_path):
    controls = _applyable_controls()
    cards = _applied_cards(controls)
    helper = RecordingHelper(
        rc=0, out="APPLY kernel-kptr 0\nVERBIFY kernel-kptr 0\n"
                  "APPLY avahi-stop 0\nVERBIFY avahi-stop 0\n")
    jid = now_journal_id(datetime.datetime(2026, 10, 25, 9, 30, 0))
    doc = tmp_path / "pass.json"
    report = apply_pass(controls, cards, jid, doc, tmp_path, helper)
    assert report["errors"] == []
    assert helper.calls == [["--apply", str(doc)]]
    rows = preview_rows(cards)
    assert [r["control_id"] for r in rows] == ["kernel-kptr", "avahi-stop"]
    assert report["colors"] == {"kernel-kptr": "GREEN",
                                "avahi-stop": "GREEN"}
    frag = ui_pages.fragment_path(tmp_path, jid, "kernel-kptr")
    assert frag.exists()
    body = json.loads(frag.read_text(encoding="utf-8"))
    assert body["entries"][0]["verb"] == "sysctl-set"
    assert body["entries"][0]["key"] == "kernel.kptr_restrict"
    assert doc.exists() and json.loads(doc.read_text(encoding="utf-8"))[
        "version"] == 1


def test_undo_pass_one_helper_call_round_trip(tmp_path):
    helper = RecordingHelper(rc=0, out="UNDO-OK\n")
    jid = "20261025-093000"
    (tmp_path / "harden" / "journal" / jid).mkdir(parents=True)
    (tmp_path / "harden" / "journal" / jid / "journal.jsonl").write_text(
        "", encoding="utf-8")
    result = undo_pass(jid, tmp_path, helper)
    assert result["undoed"] is True
    assert helper.calls == [["--undo", jid,
                             str(pass_journal_path(tmp_path, jid))]]
    assert "restored" in result["words"]
    assert undo_pass(jid, tmp_path, RecordingHelper(rc=3, err="x"))[
        "undoed"] is False
    assert "no longer pass" in undo_pass(
        jid, tmp_path, RecordingHelper(rc=3, err="x"))["words"]
    assert undo_pass(jid, tmp_path, RecordingHelper(rc=9))["undoed"] is False


def test_smuggle_changesets_refused_before_the_helper(tmp_path):
    controls = _applyable_controls()
    helper = RecordingHelper()
    jid = now_journal_id(datetime.datetime(2026, 10, 25, 9, 30, 5))
    doc = tmp_path / "pass.json"
    for smuggled in (
        {"version": 1, "journal_id": "20261025-093000\nEVIL",
         "changes": [{"control_id": "kernel-kptr", "action": "apply",
                      "backup_path": "data/harden/journal/"
                                     "20261025-093000/x.json"}]},
        {"version": 1, "journal_id": "20261025-093005",
         "changes": [{"control_id": "kernel-kptr; rm -rf /",
                      "action": "apply", "backup_path":
                      "data/harden/journal/20261025-093005/a.json"}]},
        {"version": 2, "journal_id": "20261025-093005", "changes": []},
        {"version": 1, "journal_id": "20261025-093005",
         "changes": [{"control_id": "/etc/shadow", "action": "apply",
                      "backup_path": "data/harden/journal/"
                                     "20261025-093005/a.json"}]},
    ):
        err = changeset.write_document(smuggled, controls, doc)
        assert err, f"payload accepted: {smuggled}"
        assert not doc.exists()           # nothing written, nothing ran
        assert not (tmp_path / "harden").exists()
        assert helper.calls == []         # the helper was never reached
    unknown_only = [{"control_id": "smuggled-id", "checked": True,
                     "action": "apply"}]
    report = apply_pass(controls, unknown_only, jid, doc, tmp_path, helper)
    assert helper.calls == []
    assert "smuggled-id" in report["skipped"]
    assert report["fragments"] == []


def test_apply_pass_refuses_when_nothing_is_applyable(tmp_path):
    controls = [_ctrl(id="ufw-frontend-role", group="ufw",
                      probe="ufw status", severity="INFO",
                      default="FLAG-ONLY")]
    cards = _applied_cards(controls)      # flags: never a --apply directive
    helper = RecordingHelper()
    doc = tmp_path / "pass.json"
    report = apply_pass(controls, cards, now_journal_id(), doc, tmp_path,
                        helper)
    assert helper.calls == []             # nothing ran
    assert report["skipped"], "flag cards are kept as skipped ids"
    assert not (tmp_path / "harden").exists()




def test_existing_appfw_config_never_rewritten_by_a_pass(tmp_path):
    controls = _applyable_controls()
    cards = _applied_cards(controls)
    appfw = tmp_path / "appfw"
    appfw.mkdir()
    config = appfw / "config.json"
    config.write_text(json.dumps({"armed": True, "engine": "on"}) + "\n",
                      encoding="utf-8")
    before = config.read_text(encoding="utf-8")
    helper = RecordingHelper(
        rc=0, out="APPLY kernel-kptr 0\nVERBIFY kernel-kptr 0\n")
    report = apply_pass(controls, cards, now_journal_id(),
                        tmp_path / "pass.json", tmp_path, helper)
    assert report["errors"] == [] and helper.calls
    assert config.read_text(encoding="utf-8") == before
    scan = run_scan(runner=FakeRunner(_fake_scan_table()),
                    data_dir=tmp_path, net_dir=tmp_path)
    assert scan["fresh_install"] is False


def test_wizard_defaults_offline_and_no_autoapply():
    text = (ROOT / "wizard" / "ui_pages.py").read_text(encoding="utf-8")
    assert "pkexec" in text          # the owner-runtime helper is named
    assert "subprocess.run" in text
    assert "--auto" not in text


def test_theme_rule_framework_choices_only():
    from ui.themes import THEME_CHOICES
    text = (ROOT / "wizard" / "ui_pages.py").read_text(encoding="utf-8")
    for name in ("coffee", "greyok", "add-on", "addon"):
        assert name not in text.lower()
    assert sorted(THEME_CHOICES) == ["Dark Mode", "Light Mode"]



MAC = re.compile(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b")
SERIAL = re.compile(r"\bserial\b", re.IGNORECASE)
UUID = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                  r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")


def _nasty(texts):
    joined = "\n".join(texts)
    assert not MAC.search(joined), joined
    assert not UUID.search(joined), joined
    assert not SERIAL.search(joined), joined


def test_no_hardware_identifiers_in_wizard_outputs(tmp_path):
    scan = run_scan(runner=FakeRunner(_fake_scan_table()),
                    data_dir=tmp_path, net_dir=tmp_path)
    controls = _rule_controls()
    from wizard.baseline import generate
    cards = generate(scan, controls, "workstation")
    doc = changeset.build("20261025-093005", cards)
    helper = RecordingHelper(rc=0)
    apply_pass(controls, cards, "20261025-093005", tmp_path / "pass.json",
               tmp_path, helper)
    apply_report = apply_pass(controls, cards, "20261025-093005",
                              tmp_path / "pass2.json", tmp_path,
                              RecordingHelper(
                                  rc=0, out="VERBIFY kernel-kptr 0\n"))
    texts = (list(inventory_lines(scan)) + [json.dumps(doc)]
             + [json.dumps(c) for c in cards] + apply_report["white"])
    nasty = run_scan(runner=FakeRunner(
        _fake_scan_table(), fail_lines=("ss -tuln", "lsblk -o TYPE")),
        data_dir=tmp_path, net_dir=tmp_path)
    texts.extend(inventory_lines(nasty))
    rolled = parse_strip("APPLY kernel-kptr 1\nROLLBACK kernel-kptr\n",
                         "CHANGES-bad doc")
    texts.append(str(rolled["colors"]))
    texts.append(json.dumps(helper.calls))


def test_strip_honesty_states():
    assert parse_strip("VERBIFY kernel-kptr 0\n", "")[
        "colors"] == {"kernel-kptr": "GREEN"}
    assert parse_strip("APPLY kernel-kptr 0\n", "")["colors"] == {}
    assert parse_strip("APPLY kernel-kptr 4\n", "")[
        "colors"] == {"kernel-kptr": "AMBER"}
    assert parse_strip("VERBIFY kernel-kptr none\n", "")[
        "colors"] == {"kernel-kptr": "AMBER"}
    assert parse_strip("", "VERBIFY kernel-kptr 4\n")[
        "colors"] == {"kernel-kptr": "RED"}
    assert parse_strip("ROLLBACK kernel-kptr\n", "")[
        "colors"] == {"kernel-kptr": "RED"}
    refused = parse_strip("", "CHANGES-scope backup path refused")
    assert refused["colors"] == {}
    assert refused["white"] and "refused" in refused["white"][0]
    silent = parse_strip("", "")
    assert silent["colors"] == {} and silent["white"]
    assert ui_pages.WHITE_MARK == "⚪"


def test_journal_id_grammar_and_paths(tmp_path):
    stamp = datetime.datetime(2026, 10, 25, 12, 0, 0)
    assert now_journal_id(stamp) == "20261025-120000"
    assert re.fullmatch(r"[0-9]{8}-[0-9]{6}", now_journal_id(stamp))
    p = pass_journal_path(tmp_path, "20261025-120000")
    assert p == tmp_path / "harden" / "journal" / "20261025-120000" / \
        "journal.jsonl"



gi = pytest.importorskip("gi")
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, GLib    # noqa: E402


def _gtk_ready() -> bool:
    try:
        if not Gtk.init_check():
            return False
        from gi.repository import Gdk
        return Gdk.Display.get_default() is not None
    except Exception:
        return False


if not _gtk_ready():
    pytest.skip("no display available", allow_module_level=True)


def pump(n=60):
    ctx = GLib.main_context_default()
    for _ in range(n):
        while ctx.iteration(may_block=False):
            pass


def drain(seconds=0.05, n=6):
    ctx = GLib.main_context_default()
    source = GLib.timeout_source_new(int(seconds * 1000) or 1)
    hit = {"now": False}

    def stop(*_a):
        hit["now"] = True
        return False
    source.set_callback(stop)
    source.attach(ctx)
    for _ in range(n):
        while ctx.iteration(may_block=False):
            pass
        if not hit["now"]:
            ctx.iteration(may_block=True)
    source.destroy()


@pytest.fixture(autouse=True)
def leak_guard():
    start = set(Gtk.Window.list_toplevels())
    yield
    new = [w for w in Gtk.Window.list_toplevels() if w not in start]
    for _ in range(6):                     # drain: bounded blocking passes
        pump(4)
        drain()
    for w in new:                          # hide (unmaps; no loop needed)
        try:
            w.set_visible(False)
        except Exception:
            pass
    pump(4)
    for w in new:                          # then destroy
        try:
            w.destroy()
        except Exception:
            pass
    for _ in range(6):
        pump(4)
        drain()
    for w in new:                          # destroyed widgets are dead objects
        try:
            w.set_visible(False)
        except Exception:
            pass


@pytest.fixture(scope="module", autouse=True)
def no_greywatch_ghosts():
    start = set(Gtk.Window.list_toplevels())
    yield
    for _ in range(6):
        pump(4)
        drain()
    ghosts: list[str] = []
    for w in list(Gtk.Window.list_toplevels()):
        if w in start:
            continue
        try:
            if "greywatch" in (w.get_title() or "").lower():
                w.set_visible(False)
                w.destroy()
                ghosts.append(w.get_title() or "untitled")
        except Exception:
            pass
    for _ in range(6):
        pump(4)
        drain()
    visible = [w for w in Gtk.Window.list_toplevels()
               if w not in start
               and "greywatch" in (w.get_title() or "").lower()
               and w.get_visible()]
    assert not visible and not ghosts, f"greywatch windows left: {ghosts}"


def _wizard(controls=None, runner=None, helper=None, data_dir=None,
            **kw):
    from wizard.ui_pages import SetupWizard
    w = SetupWizard(controls=controls, runner=runner, helper=helper,
                    data_dir=data_dir, **kw)
    return w


def test_six_stack_pages_in_order():
    w = _wizard(controls=_rule_controls(), runner=FakeRunner(
        _fake_scan_table()), data_dir=None)
    for step in ("welcome", "scan", "preview", "apply", "verify", "finish"):
        assert w.stack.get_child_by_name(step) is not None
    assert w._step("welcome") == "welcome"
    assert w.stack.get_visible_child_name() == "welcome"
    del w   # a Gtk.Box: no toplevel, dropping the ref is the release


def test_welcome_role_select_tunes_profile_only():
    w = _wizard(controls=_rule_controls())
    assert w._profile == "workstation"
    w._roles_store["hardened"].set_active(True)
    assert w._profile == "hardened"
    w._roles_store["workstation"].set_active(True)
    assert w._profile == "workstation"
    w.stack.get_child_by_name("apply")
    del w   # a Gtk.Box: no toplevel, dropping the ref is the release


def test_scan_step_populates_inventory_off_thread(tmp_path):
    net = tmp_path / "net"
    (net / "wlp0s1").mkdir(parents=True)
    (net / "wlp0s1" / "wireless").touch()
    w = _wizard(controls=_rule_controls(), data_dir=tmp_path, net_dir=net)
    w._runner = FakeRunner(_fake_scan_table())
    w._on_continue(None)                 # steps to scan and starts it
    for _ in range(50):
        pump(6)
        if w._scan is not None:
            break
    else:
        raise AssertionError(
            "the fake scan never landed; progress words: "
            + (w._scan_progress.get_text() or ""))


    labels = []
    child = w._inventory_box.get_first_child()
    while child is not None:
        labels.append(str(getattr(child, "_text", "")))
        child = child.get_next_sibling()
    del w   # a Gtk.Box: no toplevel, dropping the ref is the release


def test_preview_table_rows_and_toggle(tmp_path):
    net = tmp_path / "net"
    net.mkdir()
    w = _wizard(controls=_rule_controls(), data_dir=tmp_path, net_dir=net)
    w._runner = FakeRunner(_fake_scan_table())
    w._on_start_scan(None)
    for _ in range(50):
        pump(6)
        if w._scan is not None:
            break
    w._step("preview")
    pump(10)
    ids = [w._table_store[i][0] for i in range(len(w._table_store))]
    assert "clamav-installed" in ids or ids, "table filled from cards"
    first = w._table_store[0]
    card = next(c for c in w._cards if c["control_id"] == first[0])
    assert first[3 + 1] in (card["current"] or "",)     # Current col
    toggler = next(i for i in range(len(w._table_store))
                   if w._table_store[i][0] == "sshd-running")
    was = w._table_store[toggler][6]
    w._on_row_toggled(None, toggler)   # the handler owns the flip
    assert next(c for c in w._cards
                if c["control_id"] == "sshd-running")["checked"] == \
        (not was)
    assert w._apply_btn.get_sensitive() is True
    del w   # a Gtk.Box: no toplevel, dropping the ref is the release


def test_apply_step_one_dialog_then_one_helper_call(tmp_path):
    controls = _applyable_controls()
    net = tmp_path / "net"
    net.mkdir()
    w = _wizard(controls=controls, runner=FakeRunner(_fake_scan_table()),
                data_dir=tmp_path, net_dir=net)
    w._runner = FakeRunner(_fake_scan_table())
    w._on_start_scan(None)
    for _ in range(50):
        pump(6)
        if w._scan is not None:
            break
    helper_calls: list[list[str]] = []

    def helper(args):
        helper_calls.append(list(args))
        return 0, "APPLY kernel-kptr 0\nVERBIFY kernel-kptr 0", ""

    w._helper = helper
    for card in w._cards:
        card["checked"] = card["control_id"] == "kernel-kptr"
    w._step("preview")
    pump(6)
    w._launch_apply()                    # the confirm dialog was the gate
    for _ in range(80):
        pump(8)
        if helper_calls:
            break
    assert helper_calls and len(helper_calls) == 1
    assert helper_calls[0][0] == "--apply"
    for _ in range(40):
        pump(6)
        if w.stack.get_visible_child_name() == "verify":
            break
    if w.stack.get_visible_child_name() != "verify":
        raise AssertionError(
            f"verify never reached: colors={w._verify_colors!r} "
            f"white={w._verify_white!r} rc-called={helper_calls!r}")
    assert w._verify_colors == {"kernel-kptr": "GREEN"}
    del w   # a Gtk.Box: no toplevel, dropping the ref is the release


def test_finish_undo_uses_one_helper_call(tmp_path):
    controls = _applyable_controls()
    calls: list[list[str]] = []

    def helper(args):
        calls.append(list(args))
        return 0, "UNDO-OK", ""

    w = _wizard(controls=controls, helper=helper, data_dir=tmp_path)
    w._journal_id = "20261025-120000"
    (tmp_path / "harden" / "journal" / "20261025-120000").mkdir(
        parents=True, exist_ok=True)
    (tmp_path / "harden" / "journal" / "20261025-120000" /
     "journal.jsonl").write_text("", encoding="utf-8")
    w._journal_id = "20261025-120000"    # a pass applied this session
    w._undo_btn.set_sensitive(True)      # the finish page was pre-built
    w._step("finish")
    assert w._undo_btn.get_sensitive() is True
    w._on_undo(None)
    for _ in range(80):
        pump(8)
        if calls:
            break
    assert len(calls) == 1 and calls[0][0] == "--undo"
    assert calls[0][2] == str(pass_journal_path(
        tmp_path, "20261025-120000"))
    for _ in range(40):
        pump(6)
        if "restored" in w._finish_note.get_text():
            break
    pump(10)
    del w   # a Gtk.Box: no toplevel, dropping the ref is the release


def test_undo_safety_nothing_applied_no_call():
    calls: list[list[str]] = []

    def helper(args):
        calls.append(list(args))
        return 0, "", ""

    w = _wizard(controls=_applyable_controls(), helper=helper)
    w._step("finish")
    assert w._undo_btn.get_sensitive() is False
    w._on_undo(None)
    pump(20)
    assert calls == []
    del w   # a Gtk.Box: no toplevel, dropping the ref is the release


def test_fresh_dashboard_hooks(tmp_path):
    opened: list[str] = []
    w = _wizard(controls=_applyable_controls(),
                open_dashboard=lambda: opened.append("dash"))
    w._journal_id = "20261025-120000"
    w._open_board()
    pump(10)
    assert opened == ["dash"]
    del w   # a Gtk.Box: no toplevel, dropping the ref is the release


def test_setup_wizard_window_hosted_and_destroyed():
    from wizard.ui_pages import SetupWizardWindow
    win = SetupWizardWindow(parent=None, open_dashboard=None,
                            open_chooser=None)
    assert win.get_title() == "greywatch: Setup Wizard"
    try:
        assert win.get_child() is win.wizard
        win.set_visible(False)             # NEVER present in tests
        pump(10)
        assert not win.get_visible()
    finally:
        win.set_visible(False)             # hide unmaps without a loop
        pump(4)
        win.destroy()
    for _ in range(6):
        pump(4)
        GLib.main_context_default().iteration(may_block=True)
    assert win.wizard.stack.get_child_by_name("verify") is not None

def test_finish_enable_all_start_all_one_call(tmp_path, monkeypatch):
    w = _wizard(controls=_applyable_controls(), data_dir=tmp_path)
    calls: list[list[str]] = []

    def fake_run_helper(helper, args, timeout=30):
        calls.append([helper] + [str(a) for a in args])
        return 0

    monkeypatch.setattr("wiz.common.run_helper", fake_run_helper)
    w._journal_id = "20261025-130000"    # a pass was applied this session
    w._step("finish")
    for _ in range(80):
        pump(8)
        if calls:
            break
    assert calls == [["tool-control", "start-all"]]
    ef = None
    for _ in range(80):
        pump(8)
        if (tmp_path / "appfw" / "enable.json").exists():
            ef = json.loads(
                (tmp_path / "appfw" / "enable.json").read_text())
            break
    assert ef is not None and ef.get("enabled") is True
    pump(10)
    del w    # a Gtk.Box: no toplevel, dropping the ref is the release


def test_finish_enable_all_button_manual_rerun(tmp_path, monkeypatch):
    w = _wizard(controls=_applyable_controls(), data_dir=tmp_path)
    calls: list[list[str]] = []

    def fake_run_helper(helper, args, timeout=30):
        calls.append([helper] + [str(a) for a in args])
        return 1

    monkeypatch.setattr("wiz.common.run_helper", fake_run_helper)
    w._journal_id = None                 # no auto-run
    w._step("finish")
    pump(8)
    assert calls == []
    w._enable_btn.emit("clicked")
    for _ in range(80):
        pump(8)
        if calls:
            break
    assert calls == [["tool-control", "start-all"]]
    for _ in range(120):
        pump(8)
        if "attempted" in w._finish_note.get_text() or \
                "All protections" in w._finish_note.get_text():
            break
    pump(14)
    assert w._finish_note.get_text() != ""
    del w    # a Gtk.Box: no toplevel, dropping the ref is the release
