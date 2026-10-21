"""Load and validate an exceptions file: accepted-risk findings recorded with an expiry.

The file holds a list of exceptions. Each one suppresses exactly matching findings
(rule, resource and, when given, tag) until its expiry date. Matching is exact:
no globs, no case folding. Expired, unknown-rule or never-matching exceptions are
reported by the analysis layer as low TG011 findings so they cannot rot silently.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date


class ExceptionsError(ValueError):
    pass


@dataclass
class ExceptionEntry:
    rule: str
    resource: str
    tag: str | None
    expires: date
    reason: str


def _str(v, what):
    if not isinstance(v, str) or not v.strip():
        raise ExceptionsError(f"{what} must be a non-empty string")
    return v


def load(data: dict) -> list[ExceptionEntry]:
    try:
        items = data.get("exceptions") if isinstance(data, dict) else None
        if not isinstance(items, list):
            raise ExceptionsError('exceptions file must be an object with an "exceptions" list')
        out, seen = [], set()
        for i, e in enumerate(items):
            w = f"exceptions[{i}]"
            if not isinstance(e, dict):
                raise ExceptionsError(f"{w} must be an object, got {type(e).__name__}")
            rule = _str(e.get("rule"), f"{w}.rule")
            resource = _str(e.get("resource"), f"{w}.resource")
            tag = e.get("tag")
            if tag is not None:
                tag = _str(tag, f"{w}.tag")
            expires = _str(e.get("expires"), f"{w}.expires")
            try:
                exp = date.fromisoformat(expires)
            except ValueError:
                raise ExceptionsError(f"{w}.expires must be an ISO date like 2027-03-31, got {expires!r}") from None
            reason = _str(e.get("reason"), f"{w}.reason")
            key = (rule, resource, tag)
            if key in seen:
                raise ExceptionsError(f"duplicate exception for {rule} on resource {resource!r}"
                                      + (f" tag {tag!r}" if tag else ""))
            seen.add(key)
            out.append(ExceptionEntry(rule, resource, tag, exp, reason))
        return out
    except (TypeError, AttributeError) as ex:
        raise ExceptionsError(f"invalid exceptions file: {ex!r}") from ex


def load_file(path: str) -> list[ExceptionEntry]:
    with open(path, encoding="utf-8") as f:
        return load(json.load(f))
