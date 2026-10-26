import json
import os
import pathlib

REGISTRY_PATH = pathlib.Path(__file__).resolve().parent / "registry.json"


def _user_home() -> str:
    return os.environ.get("GREYWATCH_USER_HOME") or str(
        pathlib.Path(__file__).resolve().parents[1])


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
    tools = json.loads(pathlib.Path(path).read_text())["tools"]
    return [_resolve_ports(t) for t in tools]


def tool_names(registry):
    return [t["name"] for t in registry]


def get_tool(registry, name):
    for t in registry:
        if t["name"] == name:
            return t
    return None
