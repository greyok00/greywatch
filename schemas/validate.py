from __future__ import annotations

import pathlib
import re

_SCHEMA_DIR = pathlib.Path(__file__).resolve().parent
_CACHE: dict[str, dict] = {}


def load(name: str) -> dict:
    if name not in _CACHE:
        import json
        _CACHE[name] = json.loads((_SCHEMA_DIR / name).read_text())
    return _CACHE[name]


def _type_ok(value, want) -> bool:
    types = want if isinstance(want, list) else [want]
    checks = {
        "object": lambda v: isinstance(v, dict),
        "array": lambda v: isinstance(v, list),
        "string": lambda v: isinstance(v, str),
        "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
        "number": lambda v: isinstance(v, (int, float))
                   and not isinstance(v, bool),
        "boolean": lambda v: isinstance(v, bool),
        "null": lambda v: v is None,
    }
    for t in types:
        if checks.get(t, lambda v: False)(value):
            return True
    return False


def validate(doc, schema: dict, path: str = "") -> list:
    if not isinstance(schema, dict):
        return [f"{path or 'doc'}: schema not a dict"]
    errors = []
    want = schema.get("type")
    if want and not _type_ok(doc, want):
        if isinstance(doc, list) and want == "object" and \
                "items" in schema:
            pass                      # array-shaped doc; items check below
        else:
            return [f"{path or 'doc'}: expected type {want!r}"]
    if "enum" in schema and doc not in schema["enum"]:
        errors.append(f"{path or 'doc'}: {doc!r} not in enum")
    if "pattern" in schema and isinstance(doc, str) and \
            not re.match(schema["pattern"], doc):
        errors.append(f"{path}: pattern mismatch")
    for bound, cmp in (("minLength", "ge"), ("maxLength", "le")):
        if bound in schema and isinstance(doc, str):
            n = len(doc)
            ok = n >= schema[bound] if cmp == "ge" else n <= schema[bound]
            if not ok:
                errors.append(f"{path}: len {n} fails {bound}")
    if isinstance(doc, (int, float)) and not isinstance(doc, bool):
        if "min" in schema and doc < schema["min"]:
            errors.append(f"{path}: below min")
        if "max" in schema and doc > schema["max"]:
            errors.append(f"{path}: above max")
    if isinstance(doc, list):
        items = schema.get("items")
        if items:
            if "$ref" in items:       # self-ref (rules.schema.json)
                items = schema
            for i, el in enumerate(doc):
                errors += validate(el, items, f"{path}[{i}]" if path
                                   else f"[{i}]")
    if isinstance(doc, dict):
        for req in schema.get("required", []):
            if req not in doc:
                errors.append(f"{path}: missing required {req!r}")
        for key, sub in (schema.get("properties") or {}).items():
            if key in doc:
                p = f"{path}.{key}" if path else key
                errors += validate(doc[key], sub, p)
    return errors


def validate_rules(doc) -> list:
    schema = load("rules.schema.json")
    if isinstance(doc, dict) and "rules" in doc:
        return validate(doc["rules"], schema)
    if isinstance(doc, list):
        return validate(doc, schema)
    return ["rules file: neither object-with-rules nor array"]


def validate_spec(doc) -> list:
    return validate(doc, load("interaction-spec.schema.json"))


def validate_helper(helper: str, argv: list) -> list:
    doc = {"helper": helper, "argv": list(argv)}
    return validate(doc, load("helper-args.schema.json"))
