import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

CHECKER = Path(__file__).resolve().parents[1] / "scripts" / "check.py"
spec = importlib.util.spec_from_file_location("runtime_patch_check", CHECKER)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)
review = checker.review


PHP = "CVE-2026-115560"
NODE = "CVE-2026-123865"


def inventory(advisory, version, **changes):
    inv = {"asset": "portal-a", "build": "release-7", "ref": "serving-inventory-12",
           "origin": "upstream", "version": version, "serving_process_verified": True,
           "runtime": "php" if advisory == PHP else "node"}
    return {"advisory": advisory, "inventory": {**inv, **changes}}


def config(**conditions):
    return {"asset": "portal-a", "build": "release-7", "ref": "config-review-7", "conditions": conditions}


class RuntimePatchTests(unittest.TestCase):
    def test_each_documented_upstream_boundary(self):
        boundaries = {PHP: ["8.2.36", "8.3.37", "8.4.28", "8.5.13"],
                      NODE: ["22.23.5", "24.22.3", "26.13.1"]}
        for advisory, fixes in boundaries.items():
            for fixed in fixes:
                branch, last = fixed.rsplit(".", 1)
                for version, expected in [(branch + "." + str(int(last) - 1), "affected_version"),
                                           (fixed, "vendor_fix_present"),
                                           (branch + "." + str(int(last) + 1), "vendor_fix_present")]:
                    with self.subTest(advisory=advisory, version=version):
                        result = review(inventory(advisory, version))
                        self.assertEqual(result["patch_status"], expected)
                        self.assertEqual(result["first_fixed_on_branch"], fixed)
                        self.assertEqual(result["applicability"], "unknown")
                        self.assertEqual(result["evidence_refs"]["inventory"], "serving-inventory-12")
                        self.assertTrue(result["sources"][0].startswith("https://"))
        self.assertEqual(review(inventory(NODE, "v24.20.111"))["patch_status"], "affected_version")

    def test_incomplete_or_unsupported_versions(self):
        for advisory, values in [(PHP, ["8.1.99", "8.6.0", "9.0.0", "8.4.28-dev", "v8.4.28", "8"]),
                                 (NODE, ["20.0.0", "25.99.99", "27.0.0", "24.22.3-rc.1", "24.22.3+build"])]:
            for version in values + [None, 24, [], "024.22.3", " 8.4.28", "8.4.28\n", "８.４.２８"]:
                with self.subTest(advisory=advisory, version=version):
                    result = review(inventory(advisory, version))
                    self.assertEqual(result["patch_status"], "unknown")
                    self.assertIsNone(result["first_fixed_on_branch"])

    def test_distro_or_unattributed_packages(self):
        for advisory, version in [(PHP, "8.4.28"), (NODE, "v24.22.3")]:
            for origin in (None, "distribution", "custom", "header", ""):
                with self.subTest(advisory=advisory, origin=origin):
                    self.assertEqual(review(inventory(advisory, version, origin=origin))["patch_status"], "unknown")
        self.assertEqual(review(inventory(PHP, "8.4.28-1ubuntu1"))["patch_status"], "unknown")
        self.assertEqual(review(inventory(NODE, "node/24.22.3"))["patch_status"], "unknown")

    def test_deployment_identity_required_for_both_decisions(self):
        for changes in [{"ref": ""}, {"asset": "unscoped asset"}, {"build": None},
                        {"serving_process_verified": False}, {"serving_process_verified": 1},
                        {"serving_process_verified": "true"}, {"runtime": "node"}, {"ref": "x"*129}]:
            with self.subTest(changes=changes):
                req = inventory(PHP, "8.4.28", **changes)
                req["applicability"] = config(upload_progress_enabled=True, shared_session_serializer_mismatch=True)
                result = review(req)
                self.assertEqual((result["patch_status"], result["applicability"]), ("unknown", "unknown"))
        self.assertEqual(review({"advisory": NODE})["patch_status"], "unknown")

    def test_node_configuration_evaluates_independently(self):
        for value, expected in [(True, "conditions_present"), (False, "conditions_absent"), (None, "unknown")]:
            for version, patch in [("22.23.4", "affected_version"), ("22.23.5", "vendor_fix_present")]:
                result = review({**inventory(NODE, version), "applicability": config(node_handles_http2=value)})
                self.assertEqual((result["patch_status"], result["applicability"]), (patch, expected))
        result = review({**inventory(NODE, "22.23.5", origin="distribution"),
                         "applicability": config(node_handles_http2=True)})
        self.assertEqual((result["patch_status"], result["applicability"]), ("unknown", "conditions_present"))

    def test_php_configuration_needs_matching_session_evidence(self):
        for fields, expected in [
            ({}, "unknown"), ({"upload_progress_enabled": True}, "unknown"),
            ({"upload_progress_enabled": True, "shared_session_serializer_mismatch": True}, "conditions_present"),
            ({"upload_progress_enabled": False}, "conditions_absent"),
            ({"upload_progress_enabled": True, "shared_session_serializer_mismatch": False}, "conditions_absent"),
        ]:
            out = review({**inventory(PHP, "8.4.28"), "applicability": config(**fields)})
            self.assertEqual(out["applicability"], expected)
            self.assertEqual(out["evidence_refs"]["configuration"], "config-review-7")

    def test_wrong_scope_or_missing_reference_invalidates_configuration(self):
        configuration = config(node_handles_http2=True)
        for overrides in [{"asset": "other"}, {"build": "another"}, {"ref": None}]:
            result = review({**inventory(NODE, "24.22.2"), "applicability": {**configuration, **overrides}})
            self.assertEqual((result["patch_status"], result["applicability"]), ("affected_version", "unknown"))
            self.assertIsNone(result["evidence_refs"]["configuration"])

    def test_rejects_unrecognized_fields_and_invalid_flags(self):
        for data in [{}, {"advisory": "*"}, {"advisory": []}, {"advisory": PHP, "url": "ignored"},
                     {"advisory": PHP, "inventory": []},
                     {**inventory(NODE, "22.23.5"), "applicability": config(node_handles_http2=1)},
                     {**inventory(PHP, "8.5.13"), "applicability": config(node_handles_http2=True)}]:
            with self.subTest(data=data):
                with self.assertRaises(ValueError):
                    review(data)

    def test_isolated_cli_and_malformed_inputs(self):
        for input_bytes, expected in [
            (json.dumps(inventory(PHP, "8.2.35")).encode(), "affected_version"),
            (b'{"advisory":"CVE-2026-115560","inventory":{},"inventory":{}}', None),
            (b'{"advisory":"CVE-2026-115560"}' + b" " * 16384, None), (b"\xff", None),
        ]:
            run = subprocess.run([sys.executable, "-ISB", str(CHECKER)], input=input_bytes, capture_output=True)
            self.assertEqual(run.returncode, 0 if expected else 2)
            body = json.loads(run.stdout)
            if expected:
                self.assertEqual(body["patch_status"], expected)
            else:
                self.assertEqual(body["error"], "invalid_input")
                self.assertNotIn("patch_status", body)


if __name__ == "__main__":
    unittest.main()
