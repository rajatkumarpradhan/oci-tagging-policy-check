# oci-tagging-policy-check

Offline tag governance check for OCI-style resources. It reads one JSON file with a tag policy and a set of tagged resources, applies 10 rules and prints findings by severity. It can also write JSON or SARIF 2.1.0. An `import` subcommand converts an OCI-style tagging export into the inventory schema.

This is a portfolio project. The inventory format is a simplified schema I made up, not the OCI API shape. Tags here are plain key/value strings, like OCI free-form tags; there is no defined-tag namespace model. The data in `examples/` is synthetic. Nothing here has been run against a real tenancy, it calls no OCI API, and a clean result is not a compliance certification. The built-in sensitive-key list and the default tag limit are my own assumptions, not OCI constants.

## Run

```
python -m pip install -e .
tag-check examples/risky.json
tag-check examples/risky.json --output report.sarif --format sarif --fail-on high
```

Exit codes: 0 ok, 1 bad input, 2 a finding at or above `--fail-on`.

## Exceptions

Some findings are accepted risks. Record them in an exceptions file instead of deleting rules:

```
tag-check examples/risky.json --exceptions examples/exceptions.json
```

```json
{
  "exceptions": [
    {"rule": "TG004", "resource": "messy-db", "tag": "db-password",
     "expires": "2099-12-31", "reason": "Accepted while the legacy image is rebuilt; tracked in INC-1."}
  ]
}
```

- Matching is exact: `rule` id, `resource` name, and the optional `tag` (matched against the finding's tag evidence). No globs, no case folding. An exception with no `tag` suppresses every finding of that rule on that resource.
- The exception is active through its `expires` date and expires the day after.
- Expired exceptions, unknown rule ids and exceptions that match no finding are reported as low-severity TG011 findings, so accepted risks cannot rot silently.
- Suppressed findings are listed as suppressed in the console and the JSON report (`suppressed` list), and marked with a SARIF suppression in SARIF output. They do not count toward `--fail-on`; TG011 notes do.
- Policy-level findings (TG010) have no resource, so exceptions never match them.

## Import from an export

`tag-check import` converts an OCI-style tagging export into this tool's inventory JSON, so a real export can be checked without rewriting it by hand. It reads a file you already have; it does not call the OCI API.

```
tag-check import examples/export.json                     # writes inventory JSON to stdout
tag-check import examples/export.json -o inventory.json
tag-check inventory.json
```

Accepted shape: a JSON list of resources, or an object with an `items` list, in the style of `oci search resource structured-search` output. Kebab-case keys (`resource-type`) and camelCase keys (`resourceType`) are both accepted.

| Export field | Becomes |
|---|---|
| `display-name` (falls back to `identifier`) | `name` |
| `resource-type` | `kind`, lowercased (`"Instance"` becomes `"instance"`) |
| `freeform-tags` | tags, unchanged |
| `defined-tags` (`{"Namespace": {"Key": "Value"}}`) | tags flattened to `Namespace.Key` |

Rows that cannot be mapped stop the import, and every bad row is reported as `items[i]` with a best-effort line number (the line where that row's identifier or display name appears; a minified file reports line 1, the row index is always exact). The imported inventory has an empty policy, so add your own `policy` section before checking or the required-tag rules have nothing to check against.

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
| TG011 | low | exception is expired, references an unknown rule or matched no finding (only with `--exceptions`) |

## Limits

- Tags are flat key/value strings. No defined-tag namespaces, no tag defaults, no cost-tracking flag semantics. Importing flattens defined tags to `Namespace.Key`, which loses the namespace as a separate concept.
- Required-key lookup is case-insensitive; allowed values and patterns are case-sensitive. TG008 exists because those two choices can collide.
- Rules check the policy and the tags as written. They cannot tell whether a tag value is true, only whether it is allowed.
- Importer line numbers are best-effort (a text search for the row's identifier or display name), not a real JSON parse position.
- Exceptions are matched and expired-checked locally against the date on the machine running the check; there is no central exception store.

## Tests

```
python -m unittest discover -s tests -v
```

Tests cover each boundary (exact tag limit vs one over, full-match patterns, case-variant keys, blank vs missing), kind scoping, validation errors, CLI exit codes, SARIF output, the importer (defined/free-form conversion, camelCase keys, malformed rows with line numbers) and exceptions (exact matching, expiry boundaries, unknown-rule references, suppressed output in JSON and SARIF). `examples/good.json` must produce zero findings and `examples/risky.json` must trigger all 10 analysis rules (TG011 only appears via `--exceptions`).
