import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from xml.etree import ElementTree as ET

SKILL = Path(__file__).resolve().parents[1]
CHECK = SKILL / "scripts" / "check.py"


def example(name="gap"):
    return json.loads((SKILL / "examples" / (name + ".json")).read_text(encoding="utf-8"))


def invoke(raw, *args):
    run = subprocess.run([sys.executable, "-ISB", str(CHECK), *args], input=raw,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if run.stderr:
        raise AssertionError(run.stderr)
    return run.returncode, json.loads(run.stdout)


class SavedReportTests(unittest.TestCase):
    def setUp(self):
        self.scope = example()
        self.xml = ET.fromstring(self.scope["xml"])
        self.outer = self.xml.find("report")
        self.report = self.outer.find("report")
        self.results = self.report.find("results")
        self.result = self.results.find("result")
        self.override = self.result.find("overrides/override")

    def classified(self, root=None):
        self.scope["xml"] = ET.tostring(self.xml if root is None else root, encoding="unicode")
        code, out = invoke(json.dumps(self.scope).encode())
        self.assertEqual(code, 0)
        self.assertEqual(out["remediation"], "unknown")
        return out

    def option(self, name, new):
        filters = self.report.find("filters")
        keyword = filters.find("./keywords/keyword[column='%s']/value" % name)
        old = keyword.text
        keyword.text = new
        term = filters.find("term")
        term.text = term.text.replace(name + "=" + old, name + "=" + new)

    def test_packaged_examples(self):
        for name, change in [("gap", "lowered"), ("pass", "unchanged"), ("unknown", "unknown")]:
            with self.subTest(name=name):
                code, out = invoke(json.dumps(example(name)).encode())
                self.assertEqual((code, out["status"], out["score_change"]), (0, name, change))
                self.assertEqual((out["qod"], out["filters"]["min_qod"]), (80, 70))
                self.assertEqual(out["remediation"], "unknown")

    def test_native_report_forms(self):
        for root in (self.report, self.outer, self.xml):
            self.assertEqual(self.classified(root)["status"], "gap")

    def test_display_change_does_not_imply_application(self):
        self.option("apply_overrides", "0")
        out = self.classified()
        self.assertEqual((out["status"], out["score_change"]), ("unknown", "lowered"))
        self.assertEqual((out["original_severity"], out["displayed_severity"]), (8, 0))
        self.assertEqual((out["filters"]["overrides"], out["filters"]["apply_overrides"]), (True, False))

    def test_contradictory_application_filter(self):
        ET.SubElement(self.report.find("filters"), "apply_overrides").text = "0"
        self.assertEqual(self.classified()["status"], "unknown")
        self.report.find("filters/apply_overrides").text = "1"
        self.assertEqual(self.classified()["status"], "gap")
        self.report.find("filters/term").text = "apply_overrides=0"
        self.assertEqual(self.classified()["status"], "unknown")

    def test_unrelated_filters_do_not_supply_application(self):
        filters = self.report.find("filters")
        filters.remove(filters.find("keywords"))
        filters.find("term").text = 'name="demo apply_overrides=1"'
        self.assertEqual(self.classified()["status"], "unknown")

    def test_direct_filter_fields_and_absent_threshold(self):
        filters = self.report.find("filters")
        filters.clear()
        ET.SubElement(filters, "apply_overrides").text = "1"
        ET.SubElement(filters, "overrides").text = "1"
        ET.SubElement(filters, "min_qod")
        self.assertEqual(self.classified()["status"], "gap")

    def test_result_qod_is_independent_of_export_minimum(self):
        self.result.find("qod/value").text = "30"
        self.result.find("qod/type").text = "remote_banner_unreliable"
        out = self.classified()
        self.assertEqual((out["status"], out["qod"], out["filters"]["min_qod"]), ("unknown", 30, 70))
        self.option("min_qod", "0")
        for observation in (0, 30, 100):
            self.result.find("qod/value").text = str(observation)
            out = self.classified()
            self.assertEqual((out["status"], out["qod"], out["filters"]["min_qod"]), ("gap", observation, 0))
        for item in ("101", "-1", "80.0", "", "NaN"):
            self.result.find("qod/value").text = item
            self.assertEqual(self.classified()["status"], "unknown")

    def test_dynamic_vt_severity_is_an_alternative_explanation(self):
        for cvss in ("0.0", "7.9", ""):
            self.result.find("nvt/cvss_base").text = cvss
            out = self.classified()
            self.assertEqual((out["status"], out["score_change"]), ("unknown", "lowered"))
        self.result.find("nvt/cvss_base").text = "8.0"
        self.result.find("nvt/type").text = "cve"
        self.assertEqual(self.classified()["status"], "unknown")

    def test_raise_and_false_positive_label(self):
        self.option("levels", "hmlgf")
        ET.SubElement(self.report.find("filters"), "filter").text = "False Positive"
        for shown, change in (("9.0", "raised"), ("-1.0", "lowered")):
            self.result.find("severity").text = shown
            self.override.find("new_severity").text = shown
            out = self.classified()
            self.assertEqual((out["status"], out["score_change"]), ("gap", change))
        for unsupported in ("-2.0", "-3", "10.1", "9.99", "inf"):
            self.result.find("severity").text = unsupported
            self.assertEqual(self.classified()["status"], "unknown")

    def test_export_excludes_the_selected_display_level(self):
        self.option("levels", "hml")
        filters = self.report.find("filters")
        filters.remove(next(node for node in filters.findall("filter") if node.text == "Log"))
        out = self.classified()
        self.assertEqual((out["status"], out["qod"], out["score_change"]), ("unknown", 80, "lowered"))

    def test_equal_zero_and_absent_original_are_different(self):
        self.result.find("original_severity").text = "0.0"
        out = self.classified()
        self.assertEqual((out["status"], out["score_change"]), ("pass", "unchanged"))
        self.result.remove(self.result.find("original_severity"))
        out = self.classified()
        self.assertEqual((out["status"], out["original_severity"], out["displayed_severity"]), ("unknown", None, 0))

    def test_match_native_result_identity(self):
        for key, wrong in (("report_id", self.scope["result_id"]), ("result_id", self.scope["report_id"]),
                           ("host", "192.0.2.20"), ("nvt_oid", "1.2.3")):
            old = self.scope[key]
            self.scope[key] = wrong
            self.assertEqual(self.classified()["status"], "unknown")
            self.scope[key] = old
        extra = ET.SubElement(self.result, "report", id=self.scope["result_id"])
        self.assertEqual(self.classified()["status"], "unknown")
        self.result.remove(extra)
        self.report.set("id", self.scope["result_id"])
        self.assertEqual(self.classified()["status"], "unknown")

    def test_empty_duplicate_and_nested_results(self):
        self.results.remove(self.result)
        # A result elsewhere in the same report cannot fill the filtered collection.
        ET.SubElement(self.report, "other").append(self.result)
        out = self.classified()
        self.assertEqual(out["status"], "unknown")
        self.assertEqual(out["filters"]["min_qod"], 70)
        self.results.append(self.result)
        dupe = copy.deepcopy(self.result)
        dupe.find("host").text = "192.0.2.11"
        self.results.append(dupe)
        self.assertEqual(self.classified()["status"], "unknown")

    def test_scope_on_the_override(self):
        for child, prop, wrong in (("result", "id", self.scope["report_id"]), ("nvt", "oid", "1.2.3"),
                                   ("task", "id", self.scope["result_id"])):
            node = self.override.find(child)
            old = node.get(prop)
            node.set(prop, wrong)
            self.assertEqual(self.classified()["status"], "unknown")
            node.set(prop, old)
        for field, mismatch in (("active", "0"), ("orphan", "1"), ("new_severity", "8.0"),
                                ("hosts", "192.0.2.11"), ("port", "22/tcp"), ("severity", "8.1")):
            node = self.override.find(field)
            old = node.text
            node.text = mismatch
            self.assertEqual(self.classified()["status"], "unknown", field)
            node.text = old
        self.override.find("task").set("id", self.scope["result_id"])
        ET.SubElement(self.report, "task", id=self.scope["result_id"])
        self.assertEqual(self.classified()["status"], "gap")

    def test_detailed_unrestricted_scope_and_original_threshold(self):
        self.override.find("result").set("id", "")
        self.override.find("hosts").text = None
        self.override.find("port").text = None
        for old, expected in (("7.0", "gap"), ("8.0", "gap"), ("8.1", "unknown"), ("0", "unknown")):
            self.override.find("severity").text = old
            self.assertEqual(self.classified()["status"], expected)
        self.override.remove(self.override.find("hosts"))
        self.assertEqual(self.classified()["status"], "unknown")

    def test_multiple_overrides_and_other_results(self):
        self.result.find("overrides").append(copy.deepcopy(self.override))
        self.assertEqual(self.classified()["status"], "unknown")
        self.result.remove(self.result.find("overrides"))
        sibling = ET.SubElement(self.results, "result", id=self.scope["report_id"])
        ET.SubElement(sibling, "overrides").append(self.override)
        self.assertEqual(self.classified()["status"], "unknown")

    def test_ambiguous_and_inapplicable_reports(self):
        self.xml.set("status", "400")
        self.assertEqual(self.classified()["status"], "unknown")
        self.xml.set("status", "200")
        self.report.set("type", "delta")
        self.assertEqual(self.classified()["status"], "unknown")
        del self.report.attrib["type"]
        self.report.find("gmp/version").text = "22.6"
        self.assertEqual(self.classified()["status"], "unknown")
        self.report.find("gmp/version").text = "22.7"
        self.xml.append(copy.deepcopy(self.outer))
        self.assertEqual(self.classified()["status"], "unknown")

    def test_output_omits_report_content(self):
        ET.SubElement(self.result, "description").text = "private-description"
        self.report.find("filters/term").text += ' name="private-filter"'
        self.result.find("qod/type").text = "private-new-label"
        out = self.classified()
        self.assertEqual(out["status"], "gap")
        line = json.dumps(out)
        for secret in ("private-", self.scope["host"], self.scope["report_id"], self.scope["result_id"]):
            self.assertNotIn(secret, line)
        self.assertEqual(out["nvt_oid"], self.scope["nvt_oid"])
        self.assertEqual(len(out["filters"]["term_sha256"]), 64)

    def test_cli_separate_file_and_rejections(self):
        xml = self.scope.pop("xml")
        raw = json.dumps(self.scope).encode()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.xml"
            path.write_text(xml, encoding="utf-16")
            code, out = invoke(raw, "--xml-file", str(path))
            self.assertEqual((code, out["status"]), (0, "gap"))
            self.assertEqual(invoke(json.dumps(example()).encode(), "--xml-file", str(path))[0], 2)
            path.write_text("<!DOCTYPE report><report/>", encoding="utf-16")
            self.assertEqual(invoke(raw, "--xml-file", str(path))[0], 2)
        for bad in (None, [], {"xml": 3}, dict(self.scope, xml="<report>"),
                    dict(self.scope, xml="<other/>"), dict(self.scope, ref="bad alias")):
            code, out = invoke(json.dumps(bad).encode())
            self.assertEqual((code, out["error"]), (2, "invalid_input"))
        self.assertEqual(invoke(b'{"xml":"a","xml":"b"}')[0], 2)
        self.assertEqual(invoke(raw)[1]["status"], "unknown")


if __name__ == "__main__":
    unittest.main()
