"""Tool registry loader — single source of truth for labels, units, log paths.

Loaded from registry.json (versioned next to this file). Never raises on
missing/renamed log files: that is runtime state, not startup state.
"""
import json
import os
import pathlib

REGISTRY_PATH = pathlib.Path(__file__).resolve().parent / "registry.json"


def _user_home() -> str:
    """The user side of the install — the dir that CONTAINS the
    project. The daemon may run as root, so $HOME is wrong there;
    the project location is right for both users. GREYWATCH_USER_HOME
    can override for installs outside a home layout."""
    return os.environ.get("GREYWATCH_USER_HOME") or str(
        pathlib.Path(__file__).resolve().parents[1])


def default_iface() -> str:
    """The default-route interface, probed from /proc — never
    hardcoded."""
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
    """Expand ~ and {IFACE} so no real person's path ships in json."""
    home = _user_home()
    if isinstance(tool.get("logs"), list):
        tool["logs"] = [
            x.replace("{IFACE}", default_iface())
            if isinstance(x, str) else x
            for x in (x.replace("~", home, 1)
                      if isinstance(x, str) and x.startswith("~")
                      else x
                      for x in tool["logs"])]
    if isinstance(tool.get("unit"), str):
        tool["unit"] = tool["unit"].replace(
            "{IFACE}", default_iface())
    return tool


def load_registry(path=REGISTRY_PATH):
    """Return the list of ToolSpec dicts from registry.json."""
    tools = json.loads(pathlib.Path(path).read_text())["tools"]
    return [_resolve_ports(t) for t in tools]


def tool_names(registry):
    return [t["name"] for t in registry]


def get_tool(registry, name):
    for t in registry:
        if t["name"] == name:
            return t
    return None