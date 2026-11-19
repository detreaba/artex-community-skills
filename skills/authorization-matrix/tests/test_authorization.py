"""Exercise the packaged command using the examples shipped in this skill."""

import json
import subprocess
import sys
import unittest
from copy import deepcopy
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def example(name):
    return json.loads((ROOT / "examples" / (name + ".json")).read_text())


def run_checker(raw):
    return subprocess.run([sys.executable, "-IB", str(ROOT / "scripts" / "check.py")],
                          input=raw, text=True, capture_output=True, check=False)


class AuthorizationTests(unittest.TestCase):
    def checks(self, data):
        result = run_checker(json.dumps(data))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return json.loads(result.stdout)["checks"]

    def test_documented_examples(self):
        for state in ("pass", "gap", "unknown"):
            with self.subTest(state=state):
                row, = self.checks(example(state))
                self.assertEqual((row["id"], row["status"]), ("AUTH-1", state))
                self.assertEqual(row["observation_refs"], [] if state == "unknown" else ["ci-74"])

    def test_both_expected_decisions(self):
        data = example("pass")
        allowed = deepcopy(data["expectations"][0])
        allowed.update(case=2, expected="allow")
        allowed["context"].update(tenant="same", ownership="owner")
        data["expectations"].append(allowed)
        seen = deepcopy(data["observations"][0])
        seen.update(case=2, actual="allow", context=allowed["context"], ref="ci-75")
        data["observations"].append(seen)
        self.assertEqual([r["status"] for r in self.checks(data)], ["pass", "pass"])
        seen["actual"] = "deny"
        self.assertEqual([r["status"] for r in self.checks(data)], ["pass", "gap"])

    def test_conflicting_observations_and_references(self):
        data = example("pass")
        extra = deepcopy(data["observations"][0])
        extra.update(ref="ci-75", actual="allow")
        data["observations"].append(extra)
        row, = self.checks(data)
        self.assertEqual(row["status"], "unknown")
        self.assertEqual(row["observation_refs"], ["ci-74", "ci-75"])

    def test_empty_and_conflicting_policy(self):
        for expectations in ([], [example("pass")["expectations"][0], example("pass")["expectations"][0] | {"expected":"allow"}]):
            data = example("pass")
            data["expectations"] = expectations
            self.assertEqual(self.checks(data)[0]["status"], "unknown")
        self.assertEqual(self.checks({})[0]["status"], "unknown")

    def test_missing_or_incomparable_evidence(self):
        for key, value in (("asset","another-app"), ("build","another-build"), ("run","skipped"),
                           ("ref",None), ("actual",None), ("context",{})):
            with self.subTest(key=key):
                data = example("pass")
                data["observations"][0][key] = value
                self.assertEqual(self.checks(data)[0]["status"], "unknown")
        data = example("pass")
        data.pop("policy_ref")
        self.assertEqual(self.checks(data)[0]["status"], "unknown")

    def test_malformed_data_has_no_verdict(self):
        data = example("pass")
        data["expectations"][0]["case"] = True
        for raw in (json.dumps(data), '{"build":"a","build":"b"}', " " * (1024 * 1024 + 1)):
            result = run_checker(raw)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(json.loads(result.stdout), {"error": "invalid_input"})


if __name__ == "__main__":
    unittest.main()
