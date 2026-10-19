"""Load and validate the simplified tag inventory (this project's own schema, not the OCI API shape).

One file holds the tag policy and the resources. Tags here are simple key/value strings,
like OCI free-form tags; there is no defined-tag namespace model.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field


class ModelError(ValueError):
    pass


@dataclass
class Requirement:
    key: str
    values: list[str] | None = None        # allowed values; None means any value
    pattern: str | None = None             # regex the value must fully match
    kinds: list[str] | None = None         # resource kinds it applies to; None means all


@dataclass
class Policy:
    required: list[Requirement] = field(default_factory=list)
    forbidden_keys: list[str] = field(default_factory=list)
    max_tags: int = 64                     # policy-set per-resource tag limit; an assumption, not an OCI constant


@dataclass
class Resource:
    name: str
    kind: str
    tags: dict[str, str]


@dataclass
class Inventory:
    policy: Policy = field(default_factory=Policy)
    resources: list[Resource] = field(default_factory=list)


def _str(v, what):
    if not isinstance(v, str) or not v.strip():
        raise ModelError(f"{what} must be a non-empty string")
    return v


def _opt_str_list(v, what):
    if v is None:
        return None
    if not isinstance(v, list) or any(not isinstance(x, str) or not x for x in v):
        raise ModelError(f"{what} must be a list of non-empty strings")
    return v


def load(data: dict) -> Inventory:
    try:
        pol = data.get("policy", {})
        req, seen = [], set()
        for i, r in enumerate(pol.get("required", [])):
            w = f"policy.required[{i}]"
            key = _str(r["key"], f"{w}.key")
            if key.lower() in seen:
                raise ModelError(f"duplicate required tag {key!r}")
            seen.add(key.lower())
            pattern = r.get("pattern")
            if pattern is not None:
                pattern = _str(pattern, f"{w}.pattern")
                try:
                    re.compile(pattern)
                except re.error as e:
                    raise ModelError(f"{w}.pattern is not a valid regex: {e}") from None
            req.append(Requirement(key, _opt_str_list(r.get("values"), f"{w}.values"), pattern,
                                   _opt_str_list(r.get("kinds"), f"{w}.kinds")))
        forbidden = pol.get("forbidden_keys", [])
        if not isinstance(forbidden, list) or any(not isinstance(x, str) or not x.strip() for x in forbidden):
            raise ModelError("policy.forbidden_keys must be a list of non-empty strings")
        max_tags = pol.get("max_tags", 64)
        if isinstance(max_tags, bool) or not isinstance(max_tags, int) or not 1 <= max_tags <= 10000:
            raise ModelError(f"policy.max_tags must be an integer in [1, 10000], got {max_tags!r}")
        resources, names = [], set()
        for i, r in enumerate(data.get("resources", [])):
            w = f"resources[{i}]"
            name = _str(r["name"], f"{w}.name")
            if name in names:
                raise ModelError(f"duplicate resource {name!r}")
            names.add(name)
            tags = r.get("tags", {})
            if not isinstance(tags, dict):
                raise ModelError(f"{w}.tags must be an object of string to string")
            clean = {}
            for k, v in tags.items():
                if not isinstance(k, str) or not k.strip():
                    raise ModelError(f"{w}.tags has an empty key")
                if not isinstance(v, str):
                    raise ModelError(f"{w}.tags[{k!r}] must be a string, got {type(v).__name__}")
                if k in clean:
                    raise ModelError(f"{w}.tags has duplicate key {k!r}")
                clean[k] = v
            resources.append(Resource(name, _str(r["kind"], f"{w}.kind"), clean))
    except (KeyError, TypeError, AttributeError) as e:
        raise ModelError(f"invalid model: {e!r}") from e
    return Inventory(Policy(req, list(forbidden), max_tags), resources)


def load_file(path: str) -> Inventory:
    with open(path, encoding="utf-8") as f:
        return load(json.load(f))
