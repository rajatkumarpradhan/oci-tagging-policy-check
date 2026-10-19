import copy
import json
import os
import tempfile
import unittest

from tag_check import analysis, model
from tag_check.cli import main

EX = os.path.join(os.path.dirname(__file__), "..", "examples")


def ex(n):
    with open(os.path.join(EX, n), encoding="utf-8") as f:
        return json.load(f)


GOOD = ex("good.json")


def run(d):
    return analysis.analyze(model.load(d))


def rules(d):
    return {f.rule for f in run(d)}


def inv(tags=None, required=None, forbidden=None, max_tags=10, kind="compute"):
    req = required if required is not None else [{"key": "Environment", "values": ["prod", "dev"]}]
    return {"policy": {"required": req, "forbidden_keys": forbidden or [], "max_tags": max_tags},
            "resources": [{"name": "r", "kind": kind, "tags": tags if tags is not None else {"Environment": "prod"}}]}


class ExampleTests(unittest.TestCase):
    def test_good_is_clean(self):
        self.assertEqual(run(copy.deepcopy(GOOD)), [])

    def test_risky_triggers_every_rule(self):
        self.assertEqual(rules(ex("risky.json")), {f"TG{n:03d}" for n in range(1, 11)})

    def test_sorted_by_severity(self):
        s = [analysis.SEV[f.severity] for f in run(ex("risky.json"))]
        self.assertEqual(s, sorted(s))

    def test_empty(self):
        self.assertEqual(run({}), [])


class RuleTests(unittest.TestCase):
    def test_missing_required(self):
        f = [x for x in run(inv({"Owner": "a.b"})) if x.rule == "TG001"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].severity, "high")

    def test_value_not_allowed(self):
        self.assertIn("TG002", rules(inv({"Environment": "production"})))
        self.assertNotIn("TG002", rules(inv({"Environment": "dev"})))

    def test_allowed_values_are_exact(self):
        self.assertIn("TG002", rules(inv({"Environment": "PROD"})))        # case matters
        self.assertIn("TG002", rules(inv({"Environment": "prod "})))       # whitespace matters

    def test_pattern_is_full_match(self):
        req = [{"key": "CostCenter", "pattern": "CC-[0-9]{4}"}]
        self.assertNotIn("TG003", rules(inv({"CostCenter": "CC-1234"}, required=req)))
        self.assertIn("TG003", rules(inv({"CostCenter": "CC-12345"}, required=req)))
        self.assertIn("TG003", rules(inv({"CostCenter": "xCC-1234"}, required=req)))

    def test_kind_scoping(self):
        req = [{"key": "DataClass", "values": ["public"], "kinds": ["bucket"]}]
        self.assertIn("TG001", rules(inv({}, required=req, kind="bucket")))
        self.assertEqual(rules(inv({}, required=req, kind="compute")), {"TG006"})   # scoped rule does not apply; only the untagged note

    def test_blank_value_reported_once(self):
        r = rules(inv({"Environment": "  "}))
        self.assertIn("TG007", r)
        self.assertNotIn("TG002", r)       # not also a bad value
        self.assertNotIn("TG001", r)       # the tag is present, just blank

    def test_sensitive_keys(self):
        for k in ("api_key", "password", "Secret", "db-password"):
            with self.subTest(k=k):
                d = inv({"Environment": "prod", k: "x"}, forbidden=["db-password"])
                self.assertIn("TG004", rules(d))
        self.assertNotIn("TG004", rules(inv({"Environment": "prod", "owner": "a.b"})))

    def test_case_variant_duplicates(self):
        f = [x for x in run(inv({"Env": "a", "env": "b"})) if x.rule == "TG008"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].evidence, {"first": "Env", "second": "env"})
        self.assertNotIn("TG008", rules(inv({"Env": "a", "other": "b"})))

    def test_case_variant_still_counts_as_present(self):
        # required check is case-insensitive on the key, so "environment" satisfies "Environment"
        self.assertNotIn("TG001", rules(inv({"environment": "prod"})))

    def test_tag_limit_boundary(self):
        tags = {f"k{i}": "v" for i in range(10)}
        self.assertNotIn("TG005", rules(inv(tags, required=[], max_tags=10)))
        tags["k10"] = "v"
        f = [x for x in run(inv(tags, required=[], max_tags=10)) if x.rule == "TG005"]
        self.assertEqual(f[0].evidence, {"count": 11, "max": 10})

    def test_no_tags_at_all(self):
        r = rules(inv({}))
        self.assertIn("TG006", r)
        self.assertIn("TG001", r)          # and each required tag is missing

    def test_ungoverned_key(self):
        self.assertIn("TG009", rules(inv({"Environment": "prod", "extra": "x"})))
        self.assertNotIn("TG009", rules(inv({"Environment": "prod"})))

    def test_weak_required_rule_is_policy_lint(self):
        self.assertIn("TG010", rules(inv(required=[{"key": "Project"}])))
        self.assertNotIn("TG010", rules(inv(required=[{"key": "Project", "values": ["x"]}])))


class ValidationTests(unittest.TestCase):
    def bad(self, m):
        d = copy.deepcopy(GOOD)
        m(d)
        with self.assertRaises(model.ModelError):
            model.load(d)

    def test_errors(self):
        p = lambda d: d["policy"]["required"][0]
        r = lambda d: d["resources"][0]
        cases = [
            lambda d: p(d).update(key=""),
            lambda d: d["policy"]["required"].append({"key": "environment", "values": ["x"]}),   # duplicate, case-insensitive
            lambda d: p(d).update(pattern="[unclosed"),
            lambda d: p(d).update(values="prod"),
            lambda d: p(d).update(kinds="bucket"),
            lambda d: d["policy"].update(max_tags=0),
            lambda d: d["policy"].update(max_tags=True),
            lambda d: d["policy"].update(forbidden_keys="secret"),
            lambda d: r(d).update(tags={"a": 1}),
            lambda d: r(d).update(tags=["a"]),
            lambda d: r(d).update(kind=""),
            lambda d: d["resources"].append(copy.deepcopy(r(d))),
        ]
        for i, m in enumerate(cases):
            with self.subTest(case=i):
                self.bad(m)


class CliTests(unittest.TestCase):
    def test_exit_codes(self):
        self.assertEqual(main([os.path.join(EX, "good.json")]), 0)
        self.assertEqual(main([os.path.join(EX, "good.json"), "--fail-on", "low"]), 0)
        self.assertEqual(main([os.path.join(EX, "risky.json"), "--fail-on", "high"]), 2)
        self.assertEqual(main([os.path.join(EX, "risky.json"), "--format", "sarif"]), 1)

    def test_report_and_errors(self):
        with tempfile.TemporaryDirectory() as t:
            out = os.path.join(t, "r.json")
            main([os.path.join(EX, "risky.json"), "--output", out])
            rep = json.load(open(out, encoding="utf-8"))
            self.assertIn("Not tested against a live tenancy", rep["disclaimer"])
            self.assertGreater(len(rep["findings"]), 10)
            bad = os.path.join(t, "b.json")
            open(bad, "w").write("{oops")
            self.assertEqual(main([bad]), 1)
            self.assertEqual(main([os.path.join(t, "none.json")]), 1)


if __name__ == "__main__":
    unittest.main()
