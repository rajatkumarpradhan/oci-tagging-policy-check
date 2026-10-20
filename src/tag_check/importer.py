"""Convert a realistic tagging export into this tool's simplified inventory JSON.

Accepted shape: a JSON list of resources, or an object with an "items" list, in the
style of `oci search resource structured-search` output. Each resource needs an
identifier (OCID) or a display name, a resource-type, and optional freeform-tags /
defined-tags. Defined tags are flattened to "Namespace.Key" because the simplified
model has no namespace concept.

Line numbers in errors are best-effort: the exporter usually pretty-prints, so each
row is located by searching the raw text for its identifier (or display name). A
minified file reports line 1. Row indexes (items[i]) are always exact.
"""
from __future__ import annotations

import json


class ImportError(ValueError):
    pass


class _Lines:
    """Best-effort line lookup: find needles in the source text, scanning forward."""

    def __init__(self, text: str):
        self.text = text
        self.pos = 0

    def find(self, needle: str) -> int | None:
        i = self.text.find(needle, self.pos)
        if i < 0:
            return None
        self.pos = i + len(needle)
        return self.text.count("\n", 0, i) + 1


def _convert_row(row, where, errors):
    if not isinstance(row, dict):
        errors.append(f"{where}: must be an object, got {type(row).__name__}")
        return None

    def err(msg):
        errors.append(f"{where}: {msg}")

    ident = row.get("identifier")
    if ident is not None and (not isinstance(ident, str) or not ident.strip()):
        err("identifier must be a non-empty string")
        return None
    name = row.get("display-name", row.get("displayName"))
    if name is None:
        name = ident
    if not isinstance(name, str) or not name.strip():
        err("needs a non-empty display-name or identifier")
        return None
    rtype = row.get("resource-type", row.get("resourceType"))
    if not isinstance(rtype, str) or not rtype.strip():
        err("resource-type must be a non-empty string")
        return None
    tags = {}
    free = row.get("freeform-tags", row.get("freeformTags", {}))
    if not isinstance(free, dict):
        err("freeform-tags must be an object of string to string")
        return None
    for k, v in free.items():
        if not isinstance(k, str) or not k.strip():
            err("freeform-tags has an empty key")
            return None
        if not isinstance(v, str):
            err(f"freeform tag {k!r} must be a string, got {type(v).__name__}")
            return None
        tags[k] = v
    defined = row.get("defined-tags", row.get("definedTags", {}))
    if not isinstance(defined, dict):
        err("defined-tags must be an object of namespace to tag map")
        return None
    for ns, kv in defined.items():
        if not isinstance(ns, str) or not ns.strip():
            err("defined-tags has an empty namespace name")
            return None
        if not isinstance(kv, dict):
            err(f"defined-tags[{ns!r}] must be an object of string to string")
            return None
        for k, v in kv.items():
            if not isinstance(k, str) or not k.strip():
                err(f"defined-tags[{ns!r}] has an empty key")
                return None
            if not isinstance(v, str):
                err(f"defined tag {ns}.{k} must be a string, got {type(v).__name__}")
                return None
            flat = f"{ns}.{k}"
            if flat in tags:
                err(f"tag {flat!r} appears in both freeform-tags and defined-tags")
                return None
            tags[flat] = v
    return {"name": name, "kind": rtype.lower(), "tags": tags}


def convert(data, text: str = "") -> dict:
    """Convert one parsed export into simplified-inventory data.

    Raises ImportError listing every row that could not be mapped.
    """
    items = data.get("items") if isinstance(data, dict) else data
    if not isinstance(items, list):
        raise ImportError('export must be a JSON list of resources or an object with an "items" list')
    lines = _Lines(text)
    errors, resources, names = [], [], set()
    for i, row in enumerate(items):
        anchor = None
        if isinstance(row, dict):
            raw = row.get("identifier") or row.get("display-name") or row.get("displayName")
            if isinstance(raw, str) and raw:
                anchor = lines.find(json.dumps(raw))
        where = f"items[{i}]" + (f" (line {anchor})" if anchor else "")
        r = _convert_row(row, where, errors)
        if r is None:
            continue
        if r["name"] in names:
            errors.append(f"{where}: duplicate resource name {r['name']!r}")
            continue
        names.add(r["name"])
        resources.append(r)
    if errors:
        raise ImportError("cannot import export:\n" + "\n".join(f"  {e}" for e in errors))
    return {"policy": {}, "resources": resources}


def load_export(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        text = f.read()
    return convert(json.loads(text), text)
