import json
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
LAST = "RestrictPublicBuckets"


def fixture(name):
    return json.loads((ROOT / "examples" / (name + ".json")).read_text())


def command(raw):
    proc = subprocess.run([sys.executable, "-ISB", str(ROOT / "scripts/check.py")], input=raw,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=5)
    return proc.returncode, json.loads(proc.stdout)


class PublicAccessTests(unittest.TestCase):
    def check(self, data):
        status, result = command(json.dumps(data).encode())
        self.assertEqual(status, 0, result)
        self.assertEqual(result["public_access"], "unknown")
        return result

    def test_documented_examples(self):
        for name in ("gap", "pass", "unknown"):
            with self.subTest(name=name):
                self.assertEqual(self.check(fixture(name))["status"], name)
        self.assertEqual(self.check(fixture("gap"))["disabled_required"], [LAST])

    def test_complementary_levels_and_inherited_account_can_satisfy_baseline(self):
        data = fixture("pass")
        self.assertTrue(all(self.check(data)["combined_settings"].values()))
        data["bucket_evidence"].pop("response")
        src = data["account_evidence"]["response"]["PublicAccessBlockConfiguration"]
        src.update(dict.fromkeys(src, True))
        row = self.check(data)
        self.assertEqual(row["status"], "pass")
        self.assertEqual(row["evidence"]["bucket"]["state"], "unavailable")

    def test_wrong_account_snapshot_region_or_operation_cannot_complete_bucket(self):
        for key, value in (("account", "another-owner"), ("region", "us-east-1"),
                           ("snapshot", "earlier"), ("operation", "s3api.get-public-access-block"),
                           ("ref", None)):
            with self.subTest(key=key):
                data = fixture("pass")
                data["account_evidence"][key] = value
                row = self.check(data)
                self.assertEqual(row["status"], "unknown")
                self.assertEqual(row["evidence"]["account"], {"state": "unmatched", "ref": None})
                self.assertIsNone(row["combined_settings"][LAST])
        data = fixture("pass")
        data["bucket_evidence"]["bucket"] = "different-bucket"
        self.assertEqual(self.check(data)["status"], "unknown")

    def test_disabled_requires_two_explicit_false_values(self):
        data = fixture("gap")
        del data["account_evidence"]["response"]["PublicAccessBlockConfiguration"][LAST]
        row = self.check(data)
        self.assertEqual(row["status"], "unknown")
        self.assertEqual(row["unverified_required"], [LAST])
        self.assertEqual(row["evidence"]["account"]["state"], "partial")
        self.assertEqual(row["disabled_required"], [])

    def test_gap_preserves_independent_unknown_and_respects_policy_subset(self):
        data = fixture("gap")
        del data["account_evidence"]["response"]["PublicAccessBlockConfiguration"]["IgnorePublicAcls"]
        row = self.check(data)
        self.assertEqual(row["status"], "gap")
        self.assertEqual(row["disabled_required"], [LAST])
        self.assertEqual(row["unverified_required"], ["IgnorePublicAcls"])
        data["required"] = ["BlockPublicAcls", "BlockPublicPolicy"]
        self.assertEqual(self.check(data)["status"], "pass")

    def test_unsupported_route_bucket_type_or_missing_policy(self):
        for key, value in (("access_path", "access-point"), ("bucket_type", "directory"), ("bucket", None)):
            with self.subTest(key=key):
                data = fixture("pass")
                data["scope"][key] = value
                row = self.check(data)
                self.assertEqual(row["status"], "unknown")
                self.assertTrue(all(v is None for v in row["combined_settings"].values()))
        for key in ("policy_ref", "required"):
            data = fixture("pass")
            data.pop(key)
            self.assertEqual(self.check(data)["status"], "unknown")

    def test_failures_and_missing_evidence_do_not_assert_disabled_flags(self):
        for key in ("bucket_evidence", "account_evidence"):
            data = fixture("gap")
            data.pop(key)
            self.assertEqual(self.check(data)["status"], "unknown")
        data = fixture("unknown")
        self.assertEqual(self.check(data)["evidence"]["account"]["state"], "unavailable")

    def test_account_wide_controls_require_a_reference_to_the_buckets_owner(self):
        data = fixture("pass")
        del data["scope"]["ownership_ref"]
        del data["bucket_evidence"]
        flags = data["account_evidence"]["response"]["PublicAccessBlockConfiguration"]
        flags.update(dict.fromkeys(flags, True))
        row = self.check(data)
        self.assertEqual(row["status"], "unknown")
        self.assertEqual(row["unverified_required"], data["required"])

    def test_malformed_or_ambiguous_input(self):
        config_key = "PublicAccessBlockConfiguration"
        invalid = [b"[]", b"{" + b" " * 33000, b'{"scope": {}, "scope":{}}']
        for value in ("false", 0, None):
            data = fixture("gap")
            data["bucket_evidence"]["response"][config_key][LAST] = value
            invalid.append(json.dumps(data).encode())
        data = fixture("pass")
        data["account_evidence"]["error"] = "AccessDenied"
        invalid.append(json.dumps(data).encode())
        data = fixture("pass")
        data["required"] = ["BlockPublicAcls", "BlockPublicAcls"]
        invalid.append(json.dumps(data).encode())
        for raw in invalid:
            with self.subTest(length=len(raw)):
                status, result = command(raw)
                self.assertEqual((status, result), (2, {"error": "invalid_input"}))
