"""Offline CLI expectations from the Node.js Security Working Group's record 204."""
import json
from pathlib import Path
import subprocess
import sys
import unittest


SKILL = Path(__file__).resolve().parents[1]
EXAMPLE = SKILL / "examples" / "CVE-2026-111497.json"


class NodeBrotliTests(unittest.TestCase):
    def setUp(self):
        self.record = json.loads(EXAMPLE.read_bytes())

    def check(self):
        result = subprocess.run([sys.executable, "-ISB", str(SKILL / "scripts" / "check.py")],
                                input=json.dumps(self.record).encode(), capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, (result.stderr, result.stdout))
        return json.loads(result.stdout)

    def test_published_releases_around_each_fix(self):
        # 26.13.0 was the next published release after 26.12.1.
        for before, fixed, after in (("22.23.3", "22.23.4", "22.23.5"),
                                     ("24.22.0", "24.22.1", "24.22.2"),
                                     ("26.12.0", "26.12.1", "26.13.0")):
            for version, patch in ((before, "affected_version"), (fixed, "vendor_fix_present"),
                                   (after, "vendor_fix_present")):
                with self.subTest(version=version):
                    self.record["inventory"]["version"] = version
                    row = self.check()
                    self.assertEqual((row["patch_status"], row["first_fixed_on_branch"]), (patch, fixed))
        for version, fixed in (("24.0.0", "24.22.1"), ("26.0.0", "26.12.1")):
            with self.subTest(version=version):
                self.record["inventory"]["version"] = version
                row = self.check()
                self.assertEqual((row["patch_status"], row["first_fixed_on_branch"]), ("affected_version", fixed))

    def test_patch_requires_an_attributed_serving_release_on_a_reviewed_line(self):
        original = self.record["inventory"]
        for missing in ({"version": "20.19.0"}, {"version": "23.0.0"}, {"version": "25.0.0"},
                        {"version": "27.0.0"}, {"version": "24.22.1-rc.1"},
                        {"version": "24.22.1", "origin": "distribution"},
                        {"version": "24.22.1", "origin": "custom"},
                        {"version": "24.22.1", "serving_process_verified": False}):
            with self.subTest(missing=missing):
                self.record["inventory"] = {**original, **missing}
                row = self.check()
                self.assertEqual((row["patch_status"], row["first_fixed_on_branch"]), ("unknown", None))

    def test_decoder_evidence_is_scoped_separately(self):
        row = self.check()
        self.assertEqual((row["patch_status"], row["first_fixed_on_branch"], row["applicability"]),
                         ("affected_version", "24.22.1", "conditions_present"))
        observation = self.record["applicability"]
        for flag, expected in ((False, "conditions_absent"), (None, "unknown")):
            observation["conditions"]["node_decodes_untrusted_brotli"] = flag
            row = self.check()
            self.assertEqual((row["patch_status"], row["applicability"]), ("affected_version", expected))
        observation["conditions"]["node_decodes_untrusted_brotli"] = True
        observation["build"] = "other-build"
        row = self.check()
        self.assertEqual(row["applicability"], "unknown")
        self.assertIsNone(row["evidence_refs"]["configuration"])
        del self.record["applicability"]
        self.assertEqual(self.check()["applicability"], "unknown")


if __name__ == "__main__":
    unittest.main()
