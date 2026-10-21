import json
import os
import tempfile
import unittest
from datetime import date, timedelta

from tag_check import analysis, exceptions as exc_mod, model
from tag_check.cli import main
from tag_check.sarif import to_sarif

EX = os.path.join(os.path.dirname(__file__), "..", "examples")
TODAY = date(2027, 3, 15)


def inv(tags):
    return {"policy": {"required": [{"key": "Environment", "values": ["prod"]}], "max_tags": 10},
            "resources": [{"name": "legacy-vm", "kind": "compute", "tags": tags}]}


def exc(rule, resource, expires="2027-03-31", tag=None, reason="accepted risk"):
    e = {"rule": rule, "resource": resource, "expires": expires, "reason": reason}
    if tag is not None:
        e["tag"] = tag
    return e


def run(tags, exceptions, today=TODAY):
    fs = analysis.analyze(model.load(inv(tags)))
    return analysis.apply_exceptions(fs, exc_mod.load({"exceptions": exceptions}), today)


class LoadTests(unittest.TestCase):
    def test_valid(self):
        out = exc_mod.load({"exceptions": [exc("TG004", "legacy-vm", tag="api_key")]})
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].expires, date(2027, 3, 31))

    def test_errors(self):
        cases = [
            [],
            {"exceptions": "x"},
            {"exceptions": ["x"]},
            {"exceptions": [{"resource": "r", "expires": "2027-01-01", "reason": "y"}]},
            {"exceptions": [exc("TG001", " ")]},
            {"exceptions": [exc("TG001", "r", expires="31/03/2027")]},
            {"exceptions": [exc("TG001", "r", expires="2027-13-01")]},
            {"exceptions": [exc("TG001", "r", reason="  ")]},
            {"exceptions": [exc("TG001", "r", tag="  ")]},
            {"exceptions": [exc("TG001", "r", tag=3)]},
            {"exceptions": [exc("TG001", "r"), exc("TG001", "r")]},
        ]
        for i, bad in enumerate(cases):
            with self.subTest(case=i):
                with self.assertRaises(exc_mod.ExceptionsError):
                    exc_mod.load(bad)

    def test_empty_list_ok(self):
        self.assertEqual(exc_mod.load({"exceptions": []}), [])
        with self.assertRaises(exc_mod.ExceptionsError):   # missing key is a typo, not an empty file
            exc_mod.load({})


class ApplyTests(unittest.TestCase):
    def test_exact_match_suppresses(self):
        active, suppressed, notes = run({"Environment": "prod", "api_key": "x"},
                                        [exc("TG004", "legacy-vm", tag="api_key")])
        self.assertEqual([f.rule for f in active], ["TG009"])          # api_key is also ungoverned
        self.assertEqual([f.rule for f, _ in suppressed], ["TG004"])
        self.assertEqual(notes, [])

    def test_matching_is_exact(self):
        # different resource name or rule id suppresses nothing, and the exception is reported unused
        active, suppressed, notes = run({"Environment": "prod", "api_key": "x"},
                                        [exc("TG004", "Legacy-VM"), exc("TG005", "legacy-vm")])
        self.assertEqual(len(active), 2)
        self.assertEqual(suppressed, [])
        self.assertEqual(len(notes), 2)
        self.assertTrue(all(f.rule == "TG011" and f.severity == "low" for f in notes))

    def test_expiry_boundary(self):
        still_valid = TODAY.isoformat()
        active, suppressed, notes = run({"Environment": "prod", "api_key": "x"},
                                        [exc("TG004", "legacy-vm", expires=still_valid)])
        self.assertEqual(len(suppressed), 1)
        self.assertEqual(notes, [])
        yesterday = (TODAY - timedelta(days=1)).isoformat()
        active, suppressed, notes = run({"Environment": "prod", "api_key": "x"},
                                        [exc("TG004", "legacy-vm", expires=yesterday)])
        self.assertEqual(len(active), 2)                                # finding stands again
        self.assertEqual(suppressed, [])
        self.assertEqual(len(notes), 1)
        self.assertIn("expired", notes[0].message)

    def test_unknown_rule(self):
        active, suppressed, notes = run({"Environment": "prod"}, [exc("TG999", "legacy-vm")])
        self.assertEqual(len(notes), 1)
        self.assertIn("unknown rule", notes[0].message)
        self.assertEqual(suppressed, [])

    def test_tag_scoped_match(self):
        tags = {"Environment": "prod", "team": "ops", "ticket": "INC-1"}     # two TG009 findings
        active, suppressed, notes = run(tags, [exc("TG009", "legacy-vm", tag="team")])
        self.assertEqual([f.evidence["tag"] for f in active], ["ticket"])
        self.assertEqual([f.evidence["tag"] for f, _ in suppressed], ["team"])
        self.assertEqual(notes, [])

    def test_one_exception_can_cover_many_findings(self):
        tags = {"Environment": "prod", "team": "ops", "ticket": "INC-1"}
        active, suppressed, notes = run(tags, [exc("TG009", "legacy-vm")])   # no tag: whole rule+resource
        self.assertEqual(active, [])
        self.assertEqual(len(suppressed), 2)
        self.assertEqual(notes, [])

    def test_policy_findings_not_suppressible(self):
        d = {"policy": {"required": [{"key": "Project"}]}, "resources": []}   # TG010 only
        fs = analysis.analyze(model.load(d))
        active, suppressed, notes = analysis.apply_exceptions(
            fs, exc_mod.load({"exceptions": [exc("TG010", "Project")]}), TODAY)
        self.assertEqual([f.rule for f in active], ["TG010"])
        self.assertEqual(len(notes), 1)                                       # reported unused


class CliTests(unittest.TestCase):
    def write(self, t, name, data):
        p = os.path.join(t, name)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(data, f)
        return p

    def test_suppression_report_and_fail_on(self):
        with tempfile.TemporaryDirectory() as t:
            invp = self.write(t, "inv.json", inv({"Environment": "prod", "api_key": "x"}))
            excp = self.write(t, "exc.json", {"exceptions": [exc("TG004", "legacy-vm")]})
            # TG004 is high; suppressed, so --fail-on high passes
            self.assertEqual(main([invp, "--exceptions", excp, "--fail-on", "high"]), 0)
            self.assertEqual(main([invp, "--fail-on", "high"]), 2)
            out = os.path.join(t, "r.json")
            self.assertEqual(main([invp, "--exceptions", excp, "--output", out]), 0)
            rep = json.load(open(out, encoding="utf-8"))
            self.assertEqual([f["rule"] for f in rep["findings"]], ["TG009"])
            self.assertEqual(len(rep["suppressed"]), 1)
            self.assertEqual(rep["suppressed"][0]["finding"]["rule"], "TG004")
            self.assertEqual(rep["suppressed"][0]["exception"]["expires"], "2027-03-31")

    def test_expired_exception_counts_for_fail_on(self):
        with tempfile.TemporaryDirectory() as t:
            invp = self.write(t, "inv.json", inv({"Environment": "prod"}))
            excp = self.write(t, "exc.json", {"exceptions": [exc("TG006", "legacy-vm", expires="2020-01-01")]})
            self.assertEqual(main([invp, "--exceptions", excp, "--fail-on", "low"]), 2)

    def test_bad_exceptions_file(self):
        with tempfile.TemporaryDirectory() as t:
            invp = self.write(t, "inv.json", inv({"Environment": "prod"}))
            self.assertEqual(main([invp, "--exceptions", os.path.join(t, "none.json")]), 1)
            bad = self.write(t, "bad.json", {"exceptions": [{"rule": "TG001"}]})
            self.assertEqual(main([invp, "--exceptions", bad]), 1)

    def test_example_fixture(self):
        # exceptions.json suppresses one risky finding and demonstrates two TG011 notes
        out = None
        with tempfile.TemporaryDirectory() as t:
            out = os.path.join(t, "r.json")
            self.assertEqual(main([os.path.join(EX, "risky.json"), "--exceptions",
                                   os.path.join(EX, "exceptions.json"), "--output", out]), 0)
            rep = json.load(open(out, encoding="utf-8"))
            self.assertEqual(len(rep["suppressed"]), 1)
            tg011 = [f for f in rep["findings"] if f["rule"] == "TG011"]
            self.assertEqual(len(tg011), 2)

    def test_sarif_marks_suppressed(self):
        fs = analysis.analyze(model.load_file(os.path.join(EX, "risky.json")))
        excs = exc_mod.load({"exceptions": [exc("TG004", "messy-db", tag="db-password")]})
        active, suppressed, notes = analysis.apply_exceptions(fs, excs, TODAY)
        doc = to_sarif(active + notes, "risky.json", suppressed=suppressed)
        results = doc["runs"][0]["results"]
        self.assertEqual(len(results), len(active) + len(notes) + 1)
        marked = [r for r in results if "suppressions" in r]
        self.assertEqual(len(marked), 1)
        self.assertEqual(marked[0]["suppressions"][0]["kind"], "external")


if __name__ == "__main__":
    unittest.main()
