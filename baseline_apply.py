"""baseline apply - the merged install-time apply (session brief item 1).

The product contract (owner 2026-11-14): "installed" means every
detector is armed with the config that is known to work, not merely
present. data/baseline-configs.json carries the real config (the same
values verified live on the owner's machine); levels 1-4 choose how
much of it applies in one helper pass through apply/harden.sh, which
journals the whole pass and can undo it.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile

EXIT_OK, EXIT_ERR = 0, 1


def _configs_path() -> pathlib.Path:
    override = os.environ.get("GREYWATCH_TEST_BASELINE_CONFIGS")
    if override:
        return pathlib.Path(override)
    for cand in (pathlib.Path(__file__).resolve().parent / "data"
                 / "baseline-configs.json",
                 pathlib.Path("/usr/lib/greywatch") / "data"
                 / "baseline-configs.json"):
        if cand.exists():
            return cand
    return pathlib.Path(__file__).resolve().parent / "data" \
        / "baseline-configs.json"


def load_levels() -> dict:
    try:
        doc = json.loads(_configs_path().read_text(encoding="utf-8"))
        return doc.get("levels") if isinstance(doc, dict) else {}
    except (OSError, ValueError):
        return {}


def _iface() -> str:
    try:
        from registry import default_iface
        return default_iface()
    except Exception:
        return _iface_from_ip()


def _iface_from_ip() -> str:
    try:
        out = subprocess.run(["ip", "-br", "link"], capture_output=True,
                             text=True, timeout=10).stdout
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] != "lo" and "UP" in parts[1]:
                return parts[0]
    except (OSError, subprocess.SubprocessError):
        pass
    return "none"


def build_level_plan(level: str) -> tuple[dict, str] | None:
    """{"plan": [...]} in the exact entry shape harden.sh executes.
    Returns None when the level is unknown or its file is broken."""
    levels = load_levels()
    level = str(level)
    if level not in levels:
        return None
    spec = levels[level]
    entries = []
    units = [(scope, unit.replace("{iface}", _iface()))
             for scope, unit in spec.get("units", [])]
    if units:
        entries.append({
            "id": f"baseline-l{level}-arm",
            "verb": "unit-arm",
            "what": "enable and start: " + ", ".join(u for _s, u in units),
            "units": ",".join(f"{s}:{u}" for s, u in units),
            "probe": "systemctl is-active --quiet clamav-daemon.service",
        })
    for cfg in spec.get("configs", []):
        args = [str(a).replace("{iface}", _iface()) for a in cfg["args"]]
        helper = cfg["helper"]
        from cli import helper_script
        script = helper_script(helper)
        cmd = "/bin/bash " + str(script) + " " + " ".join(
            '"' + a + '"' for a in args)
        entries.append({
            "id": f"baseline-l{level}-{cfg['tool']}",
            "verb": "sh",
            "what": cfg["what"],
            "cmd": cmd,
            "probe": _probe_for(cfg["tool"]),
        })
    from hardening.controls import load_controls
    from hardening import apply as harden_apply
    if spec.get("catalog_default_only") is not None:
        base_dir = pathlib.Path(__file__).resolve().parent
        controls = load_controls(base_dir / "data")
        if not controls:
            try:
                import gwpaths
                controls = load_controls(gwpaths.data_dir())
            except Exception:
                controls = []
        if spec["catalog_default_only"] is False:
            want = controls
        else:
            want = [c for c in controls if getattr(c, "default", False)]
        from hardening.detector import scan as detect
        findings = detect(want)
        plan, _adv = harden_apply.build_plan(findings, want)
        for e in plan:
            e.setdefault("id", f"baseline-l{level}-{e['id']}")
        entries.extend(plan)
    return {"entries": entries}, spec.get("what", "")


def _probe_for(tool: str) -> str:
    return {
        "psad": "grep -q 'ENABLE_AUTO_IDS             Y;' /etc/psad/psad.conf",
        "arpwatch": "test -f /etc/default/arpwatch && grep -q "
                    "'ARGS=\"-a -p\"' /etc/default/arpwatch",
        "fail2ban": "test -f /etc/fail2ban/jail.d/sshd.local",
    }.get(tool, "true")


def apply_level(level: str, yes: bool) -> int:
    plan = build_level_plan(level)
    if plan is None:
        print(f"greywatch baseline apply: unknown level {level!r} "
              "(levels 1-4)")
        return EXIT_ERR
    doc, what = plan
    if not doc["entries"]:
        print(f"greywatch baseline apply --level {level}: nothing to do "
              f"({what}); every check already passes")
        return EXIT_OK
    from hardening.apply import plan_document
    print(f"Baseline level {level} would apply ({what}):")
    print(plan_document(doc["entries"]))
    if not yes:
        print("Dry run. Add --yes to apply through the journaled helper.")
        return EXIT_OK
    fd, path = tempfile.mkstemp(prefix="greywatch-baseline-", suffix=".json")
    with os.fdopen(fd, "w") as fh:
        fh.write(json.dumps(doc))
    try:
        from cli import helper_script
        script = helper_script("harden")
        if not script.exists():
            print(f"greywatch baseline apply: helper {script} missing",
                  flush=True)
            return EXIT_ERR
        cmd = [str(script), "apply", path] if os.geteuid() == 0 \
            else ["pkexec", str(script), "apply", path]
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=900)
        print((proc.stdout or "").strip())
        if (proc.stderr or "").strip():
            print((proc.stderr).strip()[-400:])
        print(f"baseline level {level}: the helper reported "
              f"exit {proc.returncode}. Run `greywatch baseline` to see "
              "every tool re-checked against the config.")
        return 0 if proc.returncode == 0 else EXIT_ERR
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
