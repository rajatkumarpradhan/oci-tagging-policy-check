"""SARIF 2.1.0 output. Hand-built minimal subset; results point at the input file (no line numbers)
and name the resource or policy rule as a logical location. Not validated against the official schema or a viewer."""
from __future__ import annotations

from .analysis import Finding

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
LEVEL = {"high": "error", "medium": "warning", "low": "note"}
RULES = {
    "TG001": "Required tag is missing",
    "TG002": "Tag value is not in the allowed set",
    "TG003": "Tag value does not match the required pattern",
    "TG004": "Tag looks like a secret",
    "TG005": "Resource has more tags than the policy limit",
    "TG006": "Resource has no tags at all",
    "TG007": "Tag has a blank value",
    "TG008": "Two tags differ only by case",
    "TG009": "Tag is not covered by any policy rule",
    "TG010": "Required tag accepts any value",
    "TG011": "Exception is expired, unknown or unused",
}


def to_sarif(findings: list[Finding], artifact_uri: str, version: str = "0.3.0", suppressed=None) -> dict:
    """suppressed: optional list of (Finding, ExceptionEntry) pairs, emitted with a SARIF suppression."""
    rules = [{"id": r, "shortDescription": {"text": t}} for r, t in sorted(RULES.items())]
    index = {r["id"]: i for i, r in enumerate(rules)}
    results = []
    for f, mark in [(f, None) for f in findings] + [(f, e) for f, e in (suppressed or [])]:
        res = {"ruleId": f.rule, "level": LEVEL[f.severity], "message": {"text": f.message},
               "locations": [{"physicalLocation": {"artifactLocation": {"uri": artifact_uri}},
                              "logicalLocations": [{"name": f.subject}]}]}
        if f.rule in index:
            res["ruleIndex"] = index[f.rule]
        if f.evidence:
            res["properties"] = {"evidence": f.evidence}
        if mark is not None:
            res["suppressions"] = [{"kind": "external",
                                    "justification": f"Exception until {mark.expires.isoformat()}: {mark.reason}"}]
        results.append(res)
    return {"$schema": SCHEMA, "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "oci-tagging-policy-check", "version": version, "rules": rules}}, "results": results}]}
