"""The GUI is a visual for the CLI; the CLI is the product.

Owner law (2026-11-19, after the "Scan now" button that spawned a CLI
verb nobody had ever implemented): if the CLI cannot do it, it must not
appear in the GUI at all. This pin walks every literal
`cliapi.spawn(...)` / `cliapi.call(...)` / `cliapi.jcall(...)` first
argument in ui/*.py and fails when the named verb is not part of the
CLI's own parser.
"""
import ast
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))


def cli_verbs() -> set:
    import cli
    src = pathlib.Path(cli.__file__).read_text()
    tree = ast.parse(src)
    verbs = set()
    for node in ast.walk(tree):
        # any add_parser("name") call regardless of its receiver
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr == "add_parser" and node.args:
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                verbs.add(first.value)
    verbs.add("commands")     # the no-argument sheet verb
    return verbs


def test_every_gui_cli_verb_exists():
    import ui
    verbs = cli_verbs()
    root = pathlib.Path(ui.__file__).resolve().parent
    offenders = []
    for py in sorted(root.glob("*.py")):
        if py.name in ("cliapi.py", "run_shot.py"):
            continue
        tree = ast.parse(py.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not (isinstance(func, ast.Attribute)
                    and func.attr in ("spawn", "call", "jcall")
                    and isinstance(func.value, ast.Name)
                    and func.value.id == "cliapi"):
                continue
            if not node.args:
                continue
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                verb = first.value
                if verb not in verbs:
                    offenders.append(f"{py.name}: cliapi.{func.attr}"
                                     f"('{verb}'...) has no CLI verb")
    assert not offenders, ("the GUI references verbs the CLI does not "
                           "have (the 'Scan now' class):\n"
                           + "\n".join(offenders))


def test_the_known_lives():
    # spot-checks that the pin would have caught tonight's dead wire:
    verbs = cli_verbs()
    for wanted in ("run", "posture", "doctor", "verify", "decisions",
                   "trust", "clamav"):
        # 'clamav' is not a verb on its own - "clamav scan now" was the bug
        if wanted == "clamav":
            assert wanted not in verbs
        else:
            assert wanted in verbs
