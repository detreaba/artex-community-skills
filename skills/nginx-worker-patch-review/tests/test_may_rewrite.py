"""Exercise published May cutoffs and the evidence from one serving worker."""
import json
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
CVE = "CVE-2026-42945"


def worker(product, version):
    data = json.loads((ROOT / "examples" / (CVE + ".json")).read_bytes())
    record = data["evidence"]
    record.update(product=product, worker_version=version)
    record.pop("installed_version", None)
    record["release_provenance"].update(product=product, version=version)
    return data


def invoke(raw):
    return subprocess.run([sys.executable, "-ISB", str(ROOT / "scripts/check.py")],
                          input=raw, capture_output=True, timeout=5)


class MayRewriteTests(unittest.TestCase):
    def check(self, data, status, first=None):
        proc = invoke(json.dumps(data).encode())
        self.assertEqual((proc.returncode, proc.stderr), (0, b""), proc.stdout)
        result = json.loads(proc.stdout)
        self.assertEqual((result["patch_status"], result["first_fixed_on_branch"], result["applicability"]),
                         (status, first, "unknown"))
        if status != "unknown":
            self.assertEqual(result["observed_version"], data["evidence"]["worker_version"])
            self.assertEqual(result["worker"], data["evidence"]["worker"])
            self.assertEqual(result["release_ref"], data["evidence"]["release_provenance"]["ref"])
        return result

    def test_published_oss_boundaries(self):
        for version, status, first in (
            ("0.6.26", "outside_affected_range", None), ("0.6.27", "affected_version", None),
            ("1.29.8", "affected_version", None), ("1.30.0", "affected_version", "1.30.1"),
            ("1.30.1", "vendor_fix_present", "1.30.1"), ("1.30.2", "vendor_fix_present", "1.30.1"),
            ("1.31.0", "vendor_fix_present", "1.31.0"), ("1.31.1", "vendor_fix_present", "1.31.0"),
            ("0.6.40", "unknown", None), ("1.30.8", "unknown", None), ("1.31.10", "unknown", None),
        ):
            with self.subTest(version=version):
                self.check(worker("nginx-oss", version), status, first)

    def test_plus_cutoffs_and_reviewed_unaffected_builds(self):
        for family, prior, fixed, later in (("R32", "R32 P5", "R32 P6", "R32 P7"),
                                             ("R36", "R36 P3", "R36 P4", "R36 P5")):
            for version in (family, prior, fixed, later):
                with self.subTest(version=version):
                    self.check(worker("nginx-plus", version),
                               "affected_version" if version in (family, prior) else "vendor_fix_present", fixed)
        for version in ("PLS.37.0.0.1", "PLS.37.0.6.2", "PLS.37.3.0.1"):
            self.check(worker("nginx-plus", version), "outside_affected_range")
        for version in ("R32 P8", "R35", "R36 P9", "R37", "1.29.3", "PLS.37.0.6.1", "PLS.37.3.0.2"):
            self.check(worker("nginx-plus", version), "unknown")
        self.check(worker("nginx-oss", "R36 P4"), "unknown")

    def test_loaded_release_and_independent_provenance(self):
        for product, version in (("nginx-oss", "1.30.1"), ("nginx-plus", "R36 P4")):
            for field, value in (("worker", ""), ("worker_sha256", "f" * 64), ("deployment_verified", 1),
                                 ("source", "installed_package"), ("origin", "distribution")):
                data = worker(product, version)
                data["evidence"][field] = value
                self.check(data, "unknown")
            for field, value in (("verified", 1), ("ref", ""), ("ref", "process-artifact"),
                                 ("executable_sha256", "0" * 64), ("product", "distribution"), ("version", "R32 P6")):
                data = worker(product, version)
                data["evidence"]["release_provenance"][field] = value
                self.check(data, "unknown")

    def test_rollout_in_both_directions_and_product_specific_scope(self):
        for running, installed, status in (("R36 P3", "R36 P4", "affected_version"),
                                            ("R36 P4", "R36 P3", "vendor_fix_present")):
            data = worker("nginx-plus", running)
            data["evidence"]["installed_version"] = installed
            result = self.check(data, status, "R36 P4")
            self.assertIn("installed release differs", result["patch_reason"])
        legacy = json.loads((ROOT / "examples/pass.json").read_bytes())
        legacy["evidence"]["product"] = "nginx-plus"
        self.check(legacy, "unknown")

    def test_provenance_disclosure_and_unrecognized_installed_release(self):
        data = worker("nginx-plus", "R36 P4")
        data["evidence"]["worker_sha256"] = "c" * 64
        data["evidence"]["release_provenance"]["executable_sha256"] = "c" * 64
        data["evidence"]["installed_version"] = "R35"
        result = self.check(data, "vendor_fix_present", "R36 P4")
        for term in ("operator's provenance", "copied into both fields", "unrecognized installed release"):
            self.assertIn(term, result["patch_reason"])
        data["evidence"]["release_provenance"]["verified"] = False
        self.check(data, "unknown")
        later = self.check(worker("nginx-plus", "PLS.37.0.0.1"), "outside_affected_range")
        self.assertIn("operator's provenance", later["patch_reason"])

    def test_malformed_profiles_and_non_json_numbers(self):
        record = worker("nginx-plus", "R36 P4")
        record["evidence"]["release_provenance"]["unrecognized"] = True
        raw = json.dumps(worker("nginx-oss", "1.30.1"))
        for inp in (json.dumps(record), raw.replace('"worker-start-14"', 'NaN'),
                    raw.replace('"worker-start-14"', 'Infinity')):
            proc = invoke(inp.encode())
            self.assertEqual((proc.returncode, proc.stderr), (2, b""))
            self.assertEqual(json.loads(proc.stdout)["error"], "invalid_input")
