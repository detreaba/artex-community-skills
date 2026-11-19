"""Public CLI expectations for saved JDK 21 Flight Recorder JSON."""

import json
from pathlib import Path
import subprocess
import sys
import unittest


SKILL = Path(__file__).resolve().parents[1]
CHECK = SKILL / "scripts" / "check.py"
SEEN = "filter_seen_on_recorded_checks"
ABSENT = "filter_absent_on_recorded_check"


def event(configured, status):
    return {"type": "jdk.Deserialization", "values": {"filterConfigured": configured, "filterStatus": status}}


def request(*events, complete=True):
    return {
        "inventory": {"asset": "training-app", "build": "release-42", "instance": "jvm-start-7",
                      "ref": "recording-a", "jdk_major": 21, "deployment_verified": True},
        "export_complete": complete,
        "recording": {"events": list(events)},
    }


class ObservationTests(unittest.TestCase):
    def review(self, data):
        result = subprocess.run([sys.executable, "-ISB", str(CHECK)], input=json.dumps(data).encode(),
                                capture_output=True, timeout=5)
        self.assertEqual((result.returncode, result.stderr), (0, b""), result.stdout)
        return json.loads(result.stdout)

    def test_only_presence_on_observed_checks(self):
        data = request(*(event(True, status) for status in ("UNDECIDED", "ALLOWED", "REJECTED", None)))
        row = self.review(data)
        self.assertEqual(row["status"], SEEN)
        self.assertEqual(row["observations"], {"filter_present": 4, "filter_absent": 0, "unusable": 0})
        self.assertEqual(row["export_coverage"], "complete")
        self.assertEqual(row["scope"], {"asset": "training-app", "build": "release-42", "instance": "jvm-start-7"})
        self.assertEqual(row["evidence_refs"], {"recording": "recording-a"})

    def test_mixed_or_partial_records_preserve_direct_evidence(self):
        for complete in (True, False):
            with self.subTest(complete=complete):
                row = self.review(request(event(True, "ALLOWED"), event(False, None), complete=complete))
                self.assertEqual(row["status"], ABSENT)
                self.assertEqual(row["observations"], {"filter_present": 1, "filter_absent": 1, "unusable": 0})
        row = self.review(request(event(True, "ALLOWED"), complete=False))
        self.assertEqual((row["status"], row["export_coverage"]), ("unknown", "partial"))
        self.assertEqual(row["observations"]["filter_present"], 1)
        data = request(event(True, "UNDECIDED"))
        del data["export_complete"]
        self.assertEqual(self.review(data)["status"], "unknown")

    def test_missing_event_type_or_damaged_fields_cannot_establish_coverage(self):
        unrelated = {"type": "jdk.OtherEvent", "values": {"filterConfigured": False, "filterStatus": None}}
        for events in ((), (unrelated,)):
            self.assertEqual(self.review(request(*events))["status"], "unknown")
        for bad in (event(False, "ALLOWED"), event(1, "ALLOWED"), event("true", None),
                    event(True, "future-value"), event(True, []), {"values": {}},
                    {"type": "jdk.Deserialization", "values": {"filterConfigured": True}},
                    {"type": "jdk.Deserialization"}, None):
            with self.subTest(bad=bad):
                row = self.review(request(event(True, "ALLOWED"), bad))
                self.assertEqual((row["status"], row["export_coverage"]), ("unknown", "partial"))
                self.assertEqual(row["observations"]["unusable"], 1)
        self.assertEqual(self.review(request(event(False, None), event(False, "ALLOWED")))["status"], ABSENT)
        self.assertEqual(self.review(request(unrelated, event(True, "REJECTED")))["status"], SEEN)

    def test_generation_and_attribution_required(self):
        for k, v in (("asset", ""), ("build", " "), ("instance", None), ("ref", "/tmp/private"),
                     ("jdk_major", 17), ("jdk_major", "21"), ("jdk_major", 21.0),
                     ("deployment_verified", 1), ("deployment_verified", False)):
            with self.subTest(field=k, value=v):
                data = request(event(False, None))
                data["inventory"][k] = v
                row = self.review(data)
                self.assertEqual(row["status"], "unknown")
                self.assertIsNone(row["observations"])
        data = request(event(False, None))
        del data["inventory"]
        self.assertEqual(self.review(data)["status"], "unknown")
        self.assertEqual(self.review({"inventory": request()["inventory"]})["status"], "unknown")

    def test_examples_and_non_disclosure(self):
        for name, expected in (("gap", ABSENT), ("pass", SEEN), ("unknown", "unknown")):
            with self.subTest(example=name):
                data = json.loads((SKILL / "examples" / (name + ".json")).read_bytes())
                self.assertEqual(self.review(data)["status"], expected)
        raw = event(True, "REJECTED")
        raw["values"].update(type={"name": "private.example.Customer"},
                             eventThread={"javaName": "secret-worker"},
                             exceptionMessage="/private/location", stackTrace={"frames": ["sensitive-frame"]})
        out = json.dumps(self.review(request(raw)))
        for secret in ("private.example.Customer", "secret-worker", "/private/location", "sensitive-frame"):
            self.assertNotIn(secret, out)

    def test_invalid_input_returns_one_json_error(self):
        for raw in (b'{"export_complete":true,"export_complete":false}', b'{"inventory":[]}',
                    b'{"recording":{"events":"invalid"}}', b'{"export_complete":1}',
                    b'{"recording":{"events":[NaN]}}', b'{"recording":', b'[]', b'\xff'):
            with self.subTest(raw=raw):
                result = subprocess.run([sys.executable, "-ISB", str(CHECK)], input=raw,
                                        capture_output=True, timeout=5)
                self.assertEqual((result.returncode, result.stderr), (2, b""))
                self.assertEqual(json.loads(result.stdout)["error"], "invalid_input")


if __name__ == "__main__":
    unittest.main()
