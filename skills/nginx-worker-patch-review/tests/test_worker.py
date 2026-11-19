import json
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]


def check(cve, **observation):
    data = json.loads((ROOT / "examples/pass.json").read_text())
    data["advisory"] = cve
    data["evidence"].update(observation)
    result = subprocess.run([sys.executable, "-ISB", str(ROOT / "scripts/check.py")],
                            input=json.dumps(data), text=True, capture_output=True, check=True)
    return json.loads(result.stdout)


class WorkerTests(unittest.TestCase):
    def test_each_intro_and_both_branch_fixes(self):
        # Independent before/at values copied from the upstream range boundaries.
        for suffix, before, first in (
            ("123634", "0.6.17", "0.6.18"), ("123007", "1.9.4", "1.9.5"),
            ("121810", "1.24.0", "1.25.0"), ("123633", "1.19.6", "1.19.7"),
            ("118899", "1.12.2", "1.13.0"), ("113425", "0.5.32", "0.5.33"),
            ("125283", "0.9.5", "0.9.6"), ("120967", "1.25.4", "1.25.5"),
            ("123640", "1.15.1", "1.15.2"),
        ):
            cve = "CVE-2026-" + suffix
            for version, want, fixed in (
                (before, "outside_affected_range", None), (first, "affected_version", None),
                ("1.30.6", "affected_version", "1.30.7"), ("1.30.7", "vendor_fix_present", "1.30.7"),
                ("1.31.8", "affected_version", "1.31.9"), ("1.31.9", "vendor_fix_present", "1.31.9"),
            ):
                with self.subTest(cve=cve, version=version):
                    row = check(cve, worker_version=version)
                    self.assertEqual((row["patch_status"], row["first_fixed_on_branch"]), (want, fixed))
                    self.assertEqual(row["observed_version"], version)
                    self.assertEqual(row["applicability"], "unknown")

    def test_mainline_only_bulletin(self):
        for ver, want in (("1.30.6", "outside_affected_range"), ("1.30.7", "outside_affected_range"),
                          ("1.31.3", "outside_affected_range"), ("1.31.4", "affected_version"),
                          ("1.31.8", "affected_version"), ("1.31.9", "vendor_fix_present")):
            with self.subTest(version=ver):
                self.assertEqual(check("CVE-2026-120993", worker_version=ver)["patch_status"], want)

    def test_worker_version_controls_the_result_during_rollout(self):
        row = check("CVE-2026-123007", worker_version="1.30.6", installed_version="1.30.7")
        self.assertEqual((row["patch_status"], row["observed_version"]), ("affected_version", "1.30.6"))
        self.assertIn("installed release differs", row["patch_reason"])

    def test_uncertain_release_and_evidence(self):
        for changes in ({"product": "nginx-plus"}, {"source": "http_banner"}, {"source": "installed_package"},
                        {"worker_version": None}, {"worker_version": "1.31.9-rc1"},
                        {"worker_version": "1.32.0"}, {"origin": "distribution"}):
            with self.subTest(changes=changes):
                row = check("CVE-2026-123007", **changes)
                self.assertEqual((row["patch_status"], row["first_fixed_on_branch"]), ("unknown", None))
