from __future__ import annotations

import argparse
import json
import sys
from datetime import date

from . import analysis, exceptions as exc_mod, importer, model, sarif

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
    ap.add_argument("--exceptions", help="JSON file of accepted-risk exceptions with expiry")
    a = ap.parse_args(argv)
    if a.format == "sarif" and not a.output:
        print("error: --format sarif needs --output", file=sys.stderr)
        return 1
    try:
        inv = model.load_file(a.inventory)
    except (OSError, json.JSONDecodeError, model.ModelError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    excs = []
    if a.exceptions:
        try:
            excs = exc_mod.load_file(a.exceptions)
        except (OSError, json.JSONDecodeError, exc_mod.ExceptionsError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
    fs = analysis.analyze(inv)
    suppressed = []
    if a.exceptions:
        fs, suppressed, notes = analysis.apply_exceptions(fs, excs, date.today())
        fs = sorted(fs + notes, key=lambda f: (analysis.SEV[f.severity], f.rule, f.subject, f.message))
    for f in fs:
        print(f"[{f.severity.upper():6}] {f.rule} {f.subject}: {f.message}")
    for f, e in suppressed:
        print(f"[SUPPRESSED] {f.rule} {f.subject}: {f.message} "
              f"(exception until {e.expires.isoformat()}: {e.reason})")
    summary = f"{len(fs)} finding(s)"
    if a.exceptions:
        summary += f", {len(suppressed)} suppressed"
    summary += f" across {len(inv.resources)} resource(s), {len(inv.policy.required)} required tag rule(s)."
    print(summary)
    if a.output:
        if a.format == "sarif":
            doc = sarif.to_sarif(fs, a.inventory.replace("\\", "/"), suppressed=suppressed)
        else:
            doc = {"disclaimer": DISCLAIMER, "findings": [f.to_dict() for f in fs]}
            if a.exceptions:
                doc["suppressed"] = [
                    {"finding": f.to_dict(),
                     "exception": {"expires": e.expires.isoformat(), "reason": e.reason,
                                   **({"tag": e.tag} if e.tag is not None else {})}}
                    for f, e in suppressed]
        with open(a.output, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=1)
    if a.fail_on and any(analysis.SEV[f.severity] <= analysis.SEV[a.fail_on] for f in fs):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
