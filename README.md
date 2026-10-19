# oci-tagging-policy-check

Offline tag governance check for OCI-style resources. It reads one JSON file with a tag policy and a set of tagged resources, applies 10 rules and prints findings by severity. It can also write JSON or SARIF 2.1.0.

This is a portfolio project. The inventory format is a simplified schema I made up, not the OCI API shape. Tags here are plain key/value strings, like OCI free-form tags; there is no defined-tag namespace model. The data in `examples/` is synthetic. Nothing here has been run against a real tenancy, it calls no OCI API, and a clean result is not a compliance certification. The built-in sensitive-key list and the default tag limit are my own assumptions, not OCI constants.

## Run

```
python -m pip install -e .
tag-check examples/risky.json
tag-check examples/risky.json --output report.sarif --format sarif --fail-on high
```

Exit codes: 0 ok, 1 bad input, 2 a finding at or above `--fail-on`.

## Policy format

```json
{
  "policy": {
    "required": [
      {"key": "Environment", "values": ["prod", "staging", "dev"]},
      {"key": "Owner", "pattern": "[a-z]+\\.[a-z]+"},
      {"key": "DataClass", "values": ["public", "internal"], "kinds": ["bucket", "database"]}
    ],
    "forbidden_keys": ["db-password"],
    "max_tags": 10
  },
  "resources": [
    {"name": "orders-db", "kind": "database", "tags": {"Environment": "prod", "...": "..."}}
  ]
}
```

- `values`: the tag value must be exactly one of these (case and whitespace count).
- `pattern`: the value must fully match this regex (`re.fullmatch`).
- `kinds`: the requirement applies only to these resource kinds; omit it to apply to everything.
- `max_tags` defaults to 64 (my assumption, in the OCI free-form range but not an official limit).

## Rules

| Rule | Severity | What it flags |
|---|---|---|
| TG001 | high | required tag missing (key match is case-insensitive) |
| TG002 | medium | value not in the allowed set |
| TG003 | medium | value fails the required pattern |
| TG004 | high | tag key looks like a secret (policy `forbidden_keys` plus a built-in list: password, secret, token, apikey, private_key, ...) |
| TG005 | low | more tags on one resource than the policy limit |
| TG006 | high | resource with no tags at all |
| TG007 | medium | blank or whitespace-only value (reported instead of TG002/TG003 for that tag) |
| TG008 | low | two tags on one resource differ only by case |
| TG009 | low | tag key not covered by any policy rule |
| TG010 | low | policy lint: a required tag with neither values nor pattern accepts anything |

## Limits

- Tags are flat key/value strings. No defined-tag namespaces, no tag defaults, no cost-tracking flag semantics.
- Required-key lookup is case-insensitive; allowed values and patterns are case-sensitive. TG008 exists because those two choices can collide.
- Rules check the policy and the tags as written. They cannot tell whether a tag value is true, only whether it is allowed.

## Tests

```
python -m unittest discover -s tests -v
```

Tests cover each boundary (exact tag limit vs one over, full-match patterns, case-variant keys, blank vs missing), kind scoping, validation errors, CLI exit codes and SARIF output. `examples/good.json` must produce zero findings and `examples/risky.json` must trigger all 10 rules.
