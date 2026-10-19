"""Tag governance rules. Findings are review priorities from a simplified model, not a compliance verdict."""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass

from .model import Inventory

SEV = {"high": 0, "medium": 1, "low": 2}
SENSITIVE = ("password", "passwd", "secret", "token", "apikey", "api_key", "private_key", "privatekey", "credential")


@dataclass
class Finding:
    rule: str
    severity: str
    subject: str
    message: str
    evidence: dict

    def to_dict(self):
        return asdict(self)


def analyze(inv: Inventory) -> list[Finding]:
    out: list[Finding] = []
    pol = inv.policy
    governed = {r.key.lower() for r in pol.required}
    compiled = {r.key: re.compile(r.pattern) for r in pol.required if r.pattern is not None}
    forbidden = {k.lower() for k in pol.forbidden_keys}

    # policy lint: a required tag with neither allowed values nor a pattern accepts anything
    for r in pol.required:
        if r.values is None and r.pattern is None:
            out.append(Finding("TG010", "low", f"policy:{r.key}",
                               "Required tag has neither allowed values nor a pattern, so any non-empty value passes.", {}))

    for res in inv.resources:
        sub = f"resource:{res.name}"
        lower = {k.lower(): k for k in res.tags}

        if not res.tags:
            out.append(Finding("TG006", "high", sub, "Resource has no tags at all.", {}))

        for req in pol.required:
            if req.kinds is not None and res.kind not in req.kinds:
                continue
            actual = lower.get(req.key.lower())
            if actual is None:
                out.append(Finding("TG001", "high", sub, f"Required tag {req.key!r} is missing.", {"tag": req.key}))
                continue
            value = res.tags[actual]
            if not value.strip():
                out.append(Finding("TG007", "medium", sub, f"Tag {actual!r} has a blank value.", {"tag": actual}))
                continue                       # blank is reported once, not again as a bad value
            if req.values is not None and value not in req.values:
                out.append(Finding("TG002", "medium", sub,
                                   f"Tag {actual!r} is {value!r}, not one of {req.values}.",
                                   {"tag": actual, "value": value, "allowed": req.values}))
            if req.key in compiled and not compiled[req.key].fullmatch(value):
                out.append(Finding("TG003", "medium", sub,
                                   f"Tag {actual!r} value {value!r} does not match pattern {req.pattern!r}.",
                                   {"tag": actual, "value": value, "pattern": req.pattern}))

        for k in res.tags:
            kl = k.lower()
            if kl in forbidden or kl in SENSITIVE:
                out.append(Finding("TG004", "high", sub,
                                   f"Tag {k!r} looks like a secret. Tags are visible metadata; keep credentials out of them.",
                                   {"tag": k}))
            if kl not in governed:
                out.append(Finding("TG009", "low", sub, f"Tag {k!r} is not covered by any policy rule.", {"tag": k}))

        seen_case: dict[str, str] = {}
        for k in res.tags:
            kl = k.lower()
            if kl in seen_case and seen_case[kl] != k:
                out.append(Finding("TG008", "low", sub,
                                   f"Tags {seen_case[kl]!r} and {k!r} differ only by case; pick one spelling.",
                                   {"first": seen_case[kl], "second": k}))
            else:
                seen_case.setdefault(kl, k)

        if len(res.tags) > pol.max_tags:
            out.append(Finding("TG005", "low", sub,
                               f"Resource has {len(res.tags)} tags, over the policy limit of {pol.max_tags}.",
                               {"count": len(res.tags), "max": pol.max_tags}))

    out.sort(key=lambda f: (SEV[f.severity], f.rule, f.subject, f.message))
    return out
