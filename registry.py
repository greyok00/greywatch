import json
import os
import pathlib

REGISTRY_PATH = pathlib.Path(__file__).resolve().parent / "registry.json"


def _user_home() -> str:
    # "~" in registry log paths means the DESKTOP user's home, not whoever
    # happens to run the resolver. The root daemon must read the same logs
    # the desktop tools write, so "~" is bound to GREYWATCH_UI_USER (set by
    # the unit file, GW-02) and only then falls back to the env override /
    # own home for tests and dashboard runs. Resolving "~" to Path.home()
    # made the daemon look in /root and report every tool YELLOW.
    ui = os.environ.get("GREYWATCH_UI_USER")
    if ui:
        try:
            import pwd
            return pwd.getpwnam(ui).pw_dir
        except (KeyError, ImportError):
            pass
    return os.environ.get("GREYWATCH_USER_HOME") or str(pathlib.Path.home())


def _gw_home() -> str:
    # "{GW}" means the program home: the directory that holds registry.py.
    # Correct for a source checkout and for /opt/greywatch alike.
    return str(REGISTRY_PATH.parent)


def _state_dir() -> str:
    # "{STATE}" means the runtime state dir (where the daemon writes
    # events.jsonl, netwatch-events.jsonl, cve-cache.json, the appfw mirror).
    # That is /var/lib/greywatch on an installed machine — NOT the code dir,
    # so the old "{GW}/data/..." paths pointed at a directory that never
    # exists and the tools reading them reported YELLOW.
    from gwpaths import data_dir
    return str(data_dir())


def default_iface() -> str:
    try:
        for row in pathlib.Path("/proc/net/route").read_text()\
                .splitlines()[1:]:
            f = row.split()
            if len(f) > 7 and f[1] == "00000000":
                return f[0]
    except OSError:
        pass
    return "none"


def _resolve_ports(tool: dict) -> dict:
    gw = _gw_home()
    home = _user_home()
    if isinstance(tool.get("logs"), list):
        logs = []
        for x in tool["logs"]:
            if isinstance(x, str):
                if "{STATE}" in x:
                    x = x.replace("{STATE}", _state_dir())
                elif "{GW}" in x:
                    x = x.replace("{GW}", gw)
                elif x.startswith("~"):
                    x = x.replace("~", home, 1)
                x = x.replace("{IFACE}", default_iface())
            logs.append(x)
        tool["logs"] = logs
    if isinstance(tool.get("unit"), str):
        tool["unit"] = tool["unit"].replace(
            "{IFACE}", default_iface())
    return tool


def load_registry(path=REGISTRY_PATH):
    tools = json.loads(pathlib.Path(path).read_text())["tools"]
    return [_resolve_ports(t) for t in tools]


def tool_names(registry):
    return [t["name"] for t in registry]


def get_tool(registry, name):
    for t in registry:
        if t["name"] == name:
            return t
    return None
