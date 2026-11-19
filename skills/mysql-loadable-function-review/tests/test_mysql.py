import copy
import json
import subprocess
import sys
import unittest
from pathlib import Path

SKILL = Path(__file__).resolve().parents[1]
SCRIPT = SKILL / "scripts/check.py"


def template(label="pass"):
    return json.loads((SKILL / "examples" / (label + ".json")).read_text(encoding="utf-8"))


def cli(raw):
    proc = subprocess.run([sys.executable, "-ISB", str(SCRIPT)], input=raw,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if proc.stderr:
        raise AssertionError(proc.stderr)
    return proc.returncode, json.loads(proc.stdout)


class RegistrationReview(unittest.TestCase):
    def setUp(self):
        self.data = template()
        self.policy = self.data["policy"]
        self.evidence = self.data["evidence"]
        self.rows = self.evidence["rows"]

    def result(self):
        code, out = cli(json.dumps(self.data).encode())
        self.assertEqual(code, 0)
        return out

    def test_packaged_outcomes(self):
        for case, coverage, matched in [("gap", "partial", 1), ("pass", "complete", 2), ("unknown", "complete", 1)]:
            self.data = template(case)
            out = self.result()
            self.assertEqual((out["status"], out["export_coverage"], out["matched_rows"]), (case, coverage, matched))

    def test_null_library_is_not_a_named_provider(self):
        self.policy["allow"][1]["provider"] = "component-A"
        self.rows[1].update(UDF_USAGE_COUNT=4, PROVIDER="component-A")
        out = self.result()
        self.assertEqual(out["status"], "unknown")
        self.assertEqual(out["unresolved"], [{"row": 2, "reason": "provider_identity_unavailable"}])
        del self.policy["allow"][1]["provider"]
        self.assertEqual(self.result()["status"], "pass")
        self.rows[0]["UDF_LIBRARY"] = None
        self.assertEqual(self.result()["status"], "unknown")

    def test_native_null_is_distinct_from_missing_or_text(self):
        for missing in ("NULL", "null", "", "\\N", 0, [], "../demo.so"):
            self.rows[1]["UDF_LIBRARY"] = missing
            self.assertEqual(self.result()["unresolved"], [{"row": 2, "reason": "library_unavailable"}])
        del self.rows[1]["UDF_LIBRARY"]
        self.assertEqual(self.result()["status"], "unknown")

    def test_mysql_func_cannot_report_an_absent_component(self):
        self.policy["allow"][1]["provider"] = "component-A"
        self.evidence.update(source="mysql.func", rows=[], total={"snapshot":"snap-42","ref":"count","unfiltered_rows":0})
        out = self.result()
        self.assertEqual((out["status"], out["export_coverage"], out["gaps"]), ("unknown", "unknown", []))

    def test_usage_count_does_not_change_named_registration(self):
        for usage in (0, 9, 100):
            self.rows[0].update(UDF_USAGE_COUNT=usage, UDF_RETURN_TYPE="double")
            self.assertEqual(self.result()["status"], "pass")

    def test_duplicate_name_including_different_type(self):
        self.rows[1] = dict(self.rows[0], UDF_NAME="SUM_DEMO", UDF_LIBRARY=None)
        for kind in ("aggregate", "function"):
            self.rows[1]["UDF_TYPE"] = kind
            out = self.result()
            self.assertEqual((out["status"], out["export_coverage"], out["matched_rows"]), ("unknown", "partial", 0))
            self.assertEqual(out["unresolved"], [{"row": 1, "reason":"duplicate_name"}, {"row": 2, "reason":"duplicate_name"}])

    def test_unapproved_facts_survive_partial_coverage(self):
        self.evidence["coverage"] = "partial"
        for key, wrong, reason in (("UDF_NAME","extra_demo","unapproved_name"),
                                   ("UDF_TYPE","function","unapproved_type"),
                                   ("UDF_LIBRARY","changed.so","unapproved_library")):
            old = self.rows[0][key]
            self.rows[0][key] = wrong
            out = self.result()
            self.assertEqual((out["status"], out["gaps"]), ("gap", [{"row":1,"reason":reason}]))
            self.rows[0][key] = old

    def test_independent_gap_and_ambiguous_row(self):
        self.rows[0]["UDF_LIBRARY"] = "other.so"
        self.rows[1]["UDF_NAME"] = None
        out = self.result()
        self.assertEqual(out["status"], "gap")
        self.assertEqual(out["gaps"], [{"row":1,"reason":"unapproved_library"}])
        self.assertEqual(out["unresolved"], [{"row":2,"reason":"name_unavailable"}])

    def test_allowed_alternatives_match_one_registration(self):
        self.rows[0]["UDF_NAME"] = "SUM_DEMO"
        self.rows[0]["UDF_LIBRARY"] = "Demo.SO"
        self.assertEqual(self.result()["status"], "gap")
        self.policy["allow"].append(dict(self.policy["allow"][0], library="Demo.SO"))
        self.assertEqual(self.result()["status"], "pass")

    def test_empty_snapshot_needs_matching_total_and_complete_scope(self):
        self.rows.clear()
        self.evidence["total"]["unfiltered_rows"] = 0
        self.assertEqual(self.result()["status"], "pass")
        self.evidence["coverage"] = "partial"
        self.assertEqual(self.result()["status"], "unknown")
        self.evidence["coverage"] = "complete"
        for total in (None, False, 1, "0"):
            self.evidence["total"]["unfiltered_rows"] = total
            self.assertEqual(self.result()["status"], "unknown")
        self.evidence["total"].update(snapshot="old", unfiltered_rows=0)
        self.assertEqual(self.result()["status"], "unknown")
        del self.evidence["total"]
        self.assertEqual(self.result()["status"], "unknown")

    def test_incompatible_count_or_missing_collection(self):
        self.rows[0]["UDF_LIBRARY"] = "other.so"
        self.evidence["total"]["unfiltered_rows"] = 0
        self.assertEqual(self.result()["status"], "unknown")
        self.evidence["total"]["unfiltered_rows"] = 3
        self.assertEqual(self.result()["status"], "gap")
        del self.evidence["rows"]
        self.assertEqual(self.result()["status"], "unknown")

    def test_scope_origin_and_release_boundaries(self):
        for field, wrong in [("instance","replica-b"),("build","previous"),("origin","distribution"),("product","mariadb"),
                             ("version","8.3.99"),("version","8.5.0"),("version","8.4.6-rc1"),("server_verified",1)]:
            old = self.evidence[field]
            self.evidence[field] = wrong
            self.assertEqual(self.result()["status"], "unknown", field)
            self.evidence[field] = old
        for version in ("8.4.0","8.4.12"):
            self.evidence["version"] = version
            self.assertEqual(self.result()["status"], "pass")

    def test_allowlist_is_explicit_and_reviewed(self):
        self.policy["reviewed"] = 1
        self.assertEqual(self.result()["status"], "unknown")
        self.policy["reviewed"] = True
        del self.policy["allow"]
        self.assertEqual(self.result()["status"], "unknown")
        self.policy["allow"] = []
        self.assertEqual(len(self.result()["gaps"]), 2)

    def test_unidentified_native_rows_remain_unresolved(self):
        for name in (None, "*", "NULL", "résumé", ["bad"]):
            self.rows[0]["UDF_NAME"] = name
            self.assertEqual(self.result()["unresolved"][0]["reason"], "name_unavailable")
        self.rows[0] = "not a row"
        self.assertEqual(self.result()["status"], "unknown")

    def test_invalid_input_is_controlled_and_private(self):
        for broken in ([], {"policy":[]}, {"other":42}, {"evidence":{"snapshot":"raw sensitive string"}}):
            self.assertEqual(cli(json.dumps(broken).encode()), (2, {"error":"invalid_input","detail":"Check the policy and saved MySQL inventory format."}))
        for raw in (b'{', b'{"policy": {}, "policy": {}}', b'{"evidence": NaN}'):
            self.assertEqual(cli(raw)[0], 2)
        for change in ({"library":""},{"name":"NULL"},{"name":"a/b"},{"provider":"somewhere"}):
            data = copy.deepcopy(self.data)
            data["policy"]["allow"][0].update(change)
            self.assertEqual(cli(json.dumps(data).encode())[0], 2)
        self.rows[0]["UDF_LIBRARY"] = "customer-specific.so"
        self.rows[0]["comment"] = "customer-specific-description"
        self.assertNotIn("customer-specific", json.dumps(self.result()))


if __name__ == "__main__":
    unittest.main()
