import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def example(name="pass"):
    return json.loads((ROOT / "examples" / (name + ".json")).read_bytes())


def bind(envelope):
    native = json.dumps(envelope["report"], sort_keys=True, separators=(",", ":")).encode("ascii")
    envelope["context"]["ci"]["report_digest"] = hashlib.sha256(native).hexdigest()


def invoke(data, *args):
    raw = data if isinstance(data, bytes) else json.dumps(data).encode()
    return subprocess.run([sys.executable, "-ISB", str(ROOT / "scripts/check.py"), *args],
                          input=raw, capture_output=True, timeout=10)


class BanditTests(unittest.TestCase):
    def check(self, data, *args):
        result = invoke(data, *args)
        self.assertEqual(result.stderr, b"")
        self.assertEqual(result.returncode, 0, result.stdout)
        return json.loads(result.stdout)

    def test_genuine_reports(self):
        for status, coverage, errors in (("gap", "complete_for_expected_files", 0),
                                         ("pass", "complete_for_expected_files", 0), ("unknown", "incomplete", 1)):
            with self.subTest(status=status):
                out = self.check(example(status))
                self.assertEqual((out["status"], out["coverage"], out["processing_error_count"]), (status, coverage, errors))
                if status == "gap":
                    self.assertEqual(out["findings"], [{"rule": "B101", "file_index": 2, "line": 2,
                                                        "severity": "LOW", "confidence": "HIGH"}])

    def test_context_and_digest_entry_points(self):
        data = example("gap")
        expected = self.check(data)
        direct = self.check(data["report"])
        self.assertEqual((direct["native_finding_count"], direct["status"], direct["findings"]), (1, "unknown", []))
        with tempfile.TemporaryDirectory() as tmp:
            context_path = Path(tmp) / "context.json"
            context_path.write_text(json.dumps(data["context"]))
            self.assertEqual(self.check(data["report"], "--context", str(context_path)), expected)
        result = invoke(data["report"], "--digest")
        self.assertEqual((result.returncode, result.stdout.decode().strip()), (0, expected["report_digest"]))

    def test_changed_or_unverified_run_and_report(self):
        for key in ("asset", "build", "policy", "run_ref", "report_digest"):
            with self.subTest(key=key):
                data = example("gap")
                data["context"]["ci"][key] = ""
                out = self.check(data)
                self.assertEqual((out["status"], out["findings"], out["bound_to_ci_run"]), ("unknown", [], False))
        data = example()
        data["report"]["generated_at"] = "2026-11-01T10:00:00Z"
        self.assertEqual(self.check(data)["status"], "unknown")
        for key, value in (("baseline_applied", True), ("policy_verified", False),
                           ("unfiltered_output", False), ("run_completed", False)):
            with self.subTest(key=key):
                data = example()
                data["context"]["ci"][key] = value
                self.assertEqual(self.check(data)["status"], "unknown")

    def test_expected_files_and_suppressions(self):
        for expected in ([], ["./missing.py"], ["api.py"], ["./api.py", "./missing.py"]):
            with self.subTest(expected=expected):
                data = example()
                data["context"]["expected_files"] = expected
                self.assertEqual(self.check(data)["status"], "unknown")
        for counter in ("nosec", "skipped_tests", "loc"):
            with self.subTest(counter=counter):
                data = example()
                data["report"]["metrics"]["./api.py"][counter] = 0 if counter == "loc" else 1
                bind(data)
                self.assertEqual(self.check(data)["coverage"], "incomplete")
        data = example()
        del data["report"]["metrics"]["./api.py"]["skipped_tests"]
        bind(data)
        self.assertEqual(self.check(data)["status"], "unknown")

    def test_counts_catch_filtered_or_corrupt_rows(self):
        data = example("gap")
        data["report"]["results"] = []
        bind(data)
        out = self.check(data)
        self.assertEqual((out["status"], out["aggregate_metrics_complete"]), ("unknown", False))
        data = example("gap")
        data["report"]["results"][0]["test_id"] = "unrecognized custom rule"
        bind(data)
        out = self.check(data)
        self.assertEqual((out["status"], out["unrecognized_finding_count"]), ("unknown", 1))

    def test_processing_errors_do_not_erase_observed_findings(self):
        data = example("gap")
        data["report"]["errors"] = [{"filename": "./other.py", "reason": "Analysis failed"}]
        bind(data)
        row = self.check(data)
        self.assertEqual((row["status"], row["coverage"], len(row["findings"])), ("gap", "incomplete", 1))

    def test_output_redacts_source_paths_and_arbitrary_fields(self):
        data = example("gap")
        hidden = "/private/account/client-key"
        data["context"]["expected_files"][1] = hidden
        metrics = data["report"]["metrics"]
        metrics[hidden] = metrics.pop("./worker.py")
        issue = data["report"]["results"][0]
        issue.update(filename=hidden, code="sensitive-code", issue_text="private-issue", more_info="private-link")
        data["report"]["errors"].append({"filename": hidden, "reason": "confidential-message"})
        bind(data)
        row = self.check(data)
        self.assertEqual(row["findings"][0]["file_index"], 2)
        for secret in (hidden, "sensitive-code", "private-issue", "private-link", "confidential-message", "./api.py"):
            self.assertNotIn(secret, json.dumps(row))

    def test_malformed_inputs(self):
        repeated = example()
        repeated["context"]["expected_files"].append("./api.py")
        wrong_time = example()
        wrong_time["report"]["generated_at"] = "yesterday"
        for item in (repeated, wrong_time, [], b'{"x":1,"x":2}'):
            result = invoke(item)
            self.assertEqual((result.returncode, json.loads(result.stdout)["error"]), (2, "invalid_input"))
