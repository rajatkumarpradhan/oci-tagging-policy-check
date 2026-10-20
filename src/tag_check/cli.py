from __future__ import annotations

import argparse
import json
import sys

from . import analysis, importer, model, sarif

DISCLAIMER = ("Review priorities from a simplified model of resource tags. "
              "Not tested against a live tenancy; calls no OCI API; not a compliance certification.")


def _import_main(argv) -> int:
    ap = argparse.ArgumentParser(prog="tag-check import",
                                 description="Convert an OCI-style tagging export into the simplified inventory JSON. "
                                             "Reads a file you already have; does not call the OCI API.")
    ap.add_argument("export")
    ap.add_argument("--output", "-o", help="write the inventory here (default stdout)")
    a = ap.parse_args(argv)
    try:
        inv = importer.load_export(a.export)
    except (OSError, json.JSONDecodeError, importer.ImportError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    out = json.dumps(inv, indent=1) + "\n"
    if a.output:
        with open(a.output, "w", encoding="utf-8") as fh:
            fh.write(out)
        print(f"wrote {len(inv['resources'])} resource(s) to {a.output}", file=sys.stderr)
    else:
        sys.stdout.write(out)
    return 0


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["import"]:
        return _import_main(argv[1:])
    ap = argparse.ArgumentParser(prog="tag-check", description="Offline tag governance check (synthetic/exported data).")
    ap.add_argument("inventory")
    ap.add_argument("--output")
    ap.add_argument("--format", choices=["json", "sarif"], default="json", help="format of the --output file (default json)")
    ap.add_argument("--fail-on", choices=["high", "medium", "low"])
    a = ap.parse_args(argv)
    if a.format == "sarif" and not a.output:
        print("error: --format sarif needs --output", file=sys.stderr)
        return 1
    try:
        inv = model.load_file(a.inventory)
    except (OSError, json.JSONDecodeError, model.ModelError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    fs = analysis.analyze(inv)
    for f in fs:
        print(f"[{f.severity.upper():6}] {f.rule} {f.subject}: {f.message}")
    print(f"{len(fs)} finding(s) across {len(inv.resources)} resource(s), {len(inv.policy.required)} required tag rule(s).")
    if a.output:
        doc = sarif.to_sarif(fs, a.inventory.replace("\\", "/")) if a.format == "sarif" else \
            {"disclaimer": DISCLAIMER, "findings": [f.to_dict() for f in fs]}
        with open(a.output, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=1)
    if a.fail_on and any(analysis.SEV[f.severity] <= analysis.SEV[a.fail_on] for f in fs):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
