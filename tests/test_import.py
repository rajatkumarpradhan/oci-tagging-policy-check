import json
import os
import tempfile
import unittest

from tag_check import importer, model
from tag_check.cli import main

EX = os.path.join(os.path.dirname(__file__), "..", "examples")


def export_text():
    with open(os.path.join(EX, "export.json"), encoding="utf-8") as f:
        return f.read()


class ConvertTests(unittest.TestCase):
    def test_fixture_converts(self):
        inv = importer.convert(json.loads(export_text()))
        self.assertEqual(inv["policy"], {})
        self.assertEqual(len(inv["resources"]), 3)
        web = inv["resources"][0]
        self.assertEqual(web["name"], "web-vm")
        self.assertEqual(web["kind"], "instance")                    # resource-type lowercased
        self.assertEqual(web["tags"]["Environment"], "staging")      # free-form tag as-is
        self.assertEqual(web["tags"]["Operations.CostCenter"], "CC-1002")   # defined tag flattened

    def test_result_loads_as_inventory(self):
        inv = model.load(importer.convert(json.loads(export_text())))
        self.assertEqual(len(inv.resources), 3)

    def test_bare_list_and_camel_case(self):
        data = [{"identifier": "ocid1.x", "displayName": "r1", "resourceType": "Bucket",
                 "freeformTags": {"a": "b"}, "definedTags": {"Ns": {"K": "v"}}}]
        r = importer.convert(data)["resources"][0]
        self.assertEqual((r["name"], r["kind"], r["tags"]), ("r1", "bucket", {"a": "b", "Ns.K": "v"}))

    def test_name_falls_back_to_identifier(self):
        inv = importer.convert([{"identifier": "ocid1.only", "resource-type": "Bucket"}])
        self.assertEqual(inv["resources"][0]["name"], "ocid1.only")
        self.assertEqual(inv["resources"][0]["tags"], {})

    def test_empty_export_ok(self):
        self.assertEqual(importer.convert({"items": []}), {"policy": {}, "resources": []})

    def test_bad_top_level(self):
        for bad in ({"nope": []}, "text", 3, None):
            with self.subTest(bad=bad):
                with self.assertRaises(importer.ImportError):
                    importer.convert(bad)


class ErrorTests(unittest.TestCase):
    TEXT = """{
 "items": [
  {"identifier": "ocid1.ok", "resource-type": "Bucket", "freeform-tags": {"a": "b"}},
  {"identifier": "ocid1.badkind", "resource-type": ""},
  {"identifier": "ocid1.blank", "resource-type": "Bucket", "display-name": "  "},
  {"resource-type": "Bucket", "display-name": "noid", "defined-tags": {"Ns": {"K": 7}}}
 ]
}"""

    def test_all_bad_rows_reported_with_lines(self):
        with self.assertRaises(importer.ImportError) as cm:
            importer.convert(json.loads(self.TEXT), self.TEXT)
        msg = str(cm.exception)
        self.assertIn("items[1] (line 4): resource-type must be a non-empty string", msg)
        self.assertIn("items[2] (line 5): needs a non-empty display-name or identifier", msg)
        self.assertIn("items[3] (line 6): defined tag Ns.K must be a string, got int", msg)
        self.assertNotIn("ocid1.ok", msg)

    def test_duplicate_names(self):
        rows = [{"identifier": "ocid1.a", "display-name": "x", "resource-type": "Bucket"},
                {"identifier": "ocid1.b", "display-name": "x", "resource-type": "Bucket"}]
        with self.assertRaises(importer.ImportError) as cm:
            importer.convert(rows)
        self.assertIn("duplicate resource name 'x'", str(cm.exception))

    def test_row_not_object(self):
        with self.assertRaises(importer.ImportError) as cm:
            importer.convert(["oops"])
        self.assertIn("items[0]: must be an object", str(cm.exception))

    def test_freeform_collision_with_defined(self):
        rows = [{"identifier": "ocid1.c", "resource-type": "Bucket",
                 "freeform-tags": {"Ns.K": "a"}, "defined-tags": {"Ns": {"K": "b"}}}]
        with self.assertRaises(importer.ImportError) as cm:
            importer.convert(rows)
        self.assertIn("appears in both freeform-tags and defined-tags", str(cm.exception))


class CliTests(unittest.TestCase):
    def test_import_to_file_and_check(self):
        src = os.path.join(EX, "export.json")
        with tempfile.TemporaryDirectory() as t:
            out = os.path.join(t, "inv.json")
            self.assertEqual(main(["import", src, "-o", out]), 0)
            with open(out, encoding="utf-8") as f:
                self.assertEqual(len(json.load(f)["resources"]), 3)
            self.assertEqual(main([out]), 0)          # the imported inventory passes through the checker

    def test_import_errors(self):
        with tempfile.TemporaryDirectory() as t:
            bad = os.path.join(t, "bad.json")
            open(bad, "w").write('{"items": [{"resource-type": "Bucket"}]}')
            self.assertEqual(main(["import", bad]), 1)
            self.assertEqual(main(["import", os.path.join(t, "none.json")]), 1)
            notjson = os.path.join(t, "x.json")
            open(notjson, "w").write("{oops")
            self.assertEqual(main(["import", notjson]), 1)

    def test_plain_run_unchanged(self):
        self.assertEqual(main([os.path.join(EX, "good.json")]), 0)
        self.assertEqual(main([os.path.join(EX, "risky.json"), "--fail-on", "high"]), 2)


if __name__ == "__main__":
    unittest.main()
