import ast
import pathlib
import sys
SKIP_DIRS = {'tests', '__pycache__', '.git', 'build'}
KEEP_DOCSTRING = set()
def _is_docstring(node):
    return isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)
def _module_docstring(tree):
    if tree.body and _is_docstring(tree.body[0]):
        return tree.body[0].value.value
    return None
def _inline_docstring_argument(tree, docstring):
    if not docstring:
        return 0
    hits = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for kw in node.keywords:
            if kw.arg in {'description', 'epilog', 'help'} and isinstance(kw.value, ast.Name) and (kw.value.id == '__doc__'):
                kw.value = ast.Constant(docstring)
                hits += 1
    return hits
def _strip_docstrings(tree):
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = node.body
            if body and _is_docstring(body[0]):
                node.body = body[1:] or [ast.Pass()]
def process(path: pathlib.Path) -> tuple[bool, int, int]:
    src = path.read_text(encoding='utf-8')
    before = len(src)
    tree = ast.parse(src, filename=str(path))
    doc = None if path.stem in KEEP_DOCSTRING else _module_docstring(tree)
    _inline_docstring_argument(tree, doc)
    _strip_docstrings(tree)
    out = ast.unparse(tree)
    lines = [ln.rstrip() for ln in out.splitlines() if ln.strip()]
    out = '\n'.join(lines) + '\n'
    path.write_text(out, encoding='utf-8')
    return (True, before, len(out))
def main(root: pathlib.Path) -> int:
    ok = fail = 0
    saved = 0
    for path in sorted(root.rglob('*.py')):
        rel = path.relative_to(root)
        if any((part in SKIP_DIRS for part in rel.parts)):
            continue
        try:
            _, before, after = process(path)
            ok += 1
            saved += before - after
        except Exception as exc:
            print(f'FAIL {rel}: {exc}', file=sys.stderr)
            fail += 1
    print(f'stripped {ok} files, {fail} failures, {saved / 1024:.0f} KiB removed')
    return 1 if fail else 0
if __name__ == '__main__':
    sys.exit(main(pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else '.').resolve()))
