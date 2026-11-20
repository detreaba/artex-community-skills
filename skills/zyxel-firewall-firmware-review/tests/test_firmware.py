"""Expected outcomes from Zyxel's uOS advisory and per-model production release tables."""
import json
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
CVE = "CVE-2025-1731"
MODEL = "USG FLEX 200HP"


def row(version="V1.31(ABXE.0)", model=MODEL, status="Running"):
    return {"Status": status, "Model": model, "Version": version}


def capture(rows, **changes):
    scope = {"asset": "unit-a", "build": "boot-42"}
    return {
        "advisory": CVE, **scope,
        "inventory": {**scope, "ref": "capture-42", "origin_ref": "firmware-provenance-42",
                      "origin": "upstream", "deployment_verified": True, "source": "firmware_management",
                      "firmware_status": rows, **changes},
    }


def run_cli(raw):
    return subprocess.run([sys.executable, "-ISB", str(ROOT / "scripts" / "check.py")],
                          input=raw, capture_output=True, timeout=5)


class FirmwareTests(unittest.TestCase):
    def run_request(self, request):
        run = run_cli(json.dumps(request).encode())
        self.assertEqual((run.returncode, run.stderr), (0, b""), run.stdout)
        result = json.loads(run.stdout)
        self.assertEqual((result["advisory"], result["applicability"]), (CVE, "unknown"))
        return result

    def assert_unknown(self, request):
        result = self.run_request(request)
        self.assertEqual(result["patch_status"], "unknown")
        self.assertIsNone(result["observed_version"])
        self.assertIsNone(result["first_fixed_on_branch"])

    def test_published_releases_before_inside_and_after_affected_range(self):
        for version, status in (
            ("V1.10(ABXE.1)", "outside_affected_range"),
            ("V1.20(ABXE.0)", "affected_version"), ("V1.20(ABXE.2)", "affected_version"),
            ("V1.21(ABXE.0)C0", "affected_version"), ("V1.30(ABXE.1)", "affected_version"),
            ("V1.31(ABXE.0)C0", "affected_version"), ("V1.32(ABXE.0)", "vendor_fix_present"),
            ("V1.35(ABXE.0)C0", "vendor_fix_present"), ("V1.40(ABXE.0)C0", "vendor_fix_present"),
        ):
            with self.subTest(version=version):
                result = self.run_request(capture([row(version)]))
                self.assertEqual(result["patch_status"], status)
                self.assertEqual(result["observed_version"], version)
                fix = None if status == "outside_affected_range" else "V1.32(ABXE.0)C0"
                self.assertEqual(result["first_fixed_on_branch"], fix)
                self.assertEqual(result["scope"], {"asset": "unit-a", "build": "boot-42"})
                self.assertEqual(result["evidence_refs"]["inventory"], "capture-42")
                self.assertEqual(result["evidence_refs"]["origin"], "firmware-provenance-42")
                self.assertTrue(any("community.zyxel.com" in s for s in result["sources"]))

    def test_hardware_codes_and_first_fixed_image_for_each_model(self):
        for model, code in (("50H", "ACLO"), ("50HP", "ACLP"), ("100H", "ABXF"), ("100HP", "ACII"),
                            ("200H", "ABWV"), ("200HP", "ABXE"), ("500H", "ABZH"), ("700H", "ABZI")):
            with self.subTest(model=model):
                name = "USG FLEX " + model
                version = f"V1.32({code}.0)C0"
                result = self.run_request(capture([row(version, name)]))
                self.assertEqual((result["model"], result["patch_status"], result["first_fixed_on_branch"]),
                                 (name, "vendor_fix_present", version))
                early = self.run_request(capture([row(f"V1.31({code}.0)", name)]))
                self.assertEqual(early["patch_status"], "unknown" if model in ("50H", "50HP") else "affected_version")

    def test_cloud_or_staged_image_does_not_establish_running_release(self):
        fixed = "V1.32(ABXE.0)C0"
        for rows in ([row("V1.31(ABXE.0)"), row(fixed, status="Standby")],
                     [row("V1.31(ABXE.0)")]):
            result = self.run_request(capture(rows, cloud_latest_version=fixed))
            self.assertEqual(result["patch_status"], "affected_version")
        for request in (capture([], cloud_latest_version=fixed), capture([row(fixed, status="Standby")]),
                        capture([row(fixed)], source="cloud_firmware_information"),
                        capture([row(fixed)], source="standby_image"),
                        capture([row(fixed), row("V1.31(ABXE.0)")]),
                        capture([row(fixed), {"Version": "V1.31(ABXE.0)"}])):
            self.assert_unknown(request)

    def test_standby_hardware_code_must_agree_with_the_running_unit(self):
        fixed = row("V1.32(ABXE.0)C0")
        for version in ("V1.32(ABWV.0)C0", "V1.31(ABWV.0)b2", "", None):
            standby = row(version, status="Standby")
            for rows in ([fixed, standby], [standby, fixed]):
                self.assert_unknown(capture(rows))
        for version in ("V1.31(ABXE.0)", "V1.80(ABXE.6)b2"):
            result = self.run_request(capture([row(version, status="Standby"), fixed]))
            self.assertEqual((result["patch_status"], result["observed_version"]),
                             ("vendor_fix_present", "V1.32(ABXE.0)C0"))

    def test_other_unit_boot_or_unverified_provenance(self):
        for updates in ({"asset": "unit-b"}, {"build": "earlier-boot"}, {"ref": ""}, {"origin_ref": None},
                        {"source": None}, {"deployment_verified": False}, {"deployment_verified": 1},
                        {"origin": "hotfix"}, {"origin": "custom"}):
            with self.subTest(updates=updates):
                for version in ("V1.31(ABXE.0)", "V1.32(ABXE.0)"):
                    self.assert_unknown(capture([row(version)], **updates))

    def test_non_h_models_mislabeled_images_and_engineering_builds(self):
        for model, version in (("USG FLEX 200", "V5.39(ABUI.0)C0"), ("USG FLEX 200", "V1.32(ABXE.0)C0"),
                               (MODEL, "V1.32(ABWV.0)C0"), (MODEL, "V1.32(ABXE.0)b4s1"),
                               (MODEL, "V1.32(ABXE.0)ITS-25WK18"), (MODEL, "V1.32(ABXE.0)C1"),
                               (MODEL, "V1.32(ABXE.99)C0"), (MODEL, "V1.34(ABXE.0)C0"),
                               (MODEL, "V1.99(ABXE.0)C0"), (MODEL, "1.32"),
                               (MODEL, ["1.32"]), ([], "V1.32(ABXE.0)C0")):
            with self.subTest(model=model, version=version):
                self.assert_unknown(capture([row(version, model)]))

    def test_packaged_examples(self):
        for name, expected in (("gap", "affected_version"), ("pass", "vendor_fix_present"), ("unknown", "unknown")):
            request = json.loads((ROOT / "examples" / f"{name}.json").read_bytes())
            with self.subTest(fixture=name):
                self.assertEqual(self.run_request(request)["patch_status"], expected)

    def test_invalid_records_exit_two_with_one_error(self):
        for raw in (b"{", b"[]", b'{"advisory":"unsupported"}',
                    b'{"advisory":"CVE-2025-1731","inventory":null}',
                    json.dumps(capture({"not": "an array"})).encode(), json.dumps(capture([42])).encode(),
                    b'{"advisory":"CVE-2025-1731","inventory":{"ref":"x","ref":"y"}}',
                    b'{"advisory":"CVE-2025-1731","inventory":{"deployment_verified":Infinity}}',
                    b'{"advisory":"CVE-2025-1731"}' + b" " * 16384):
            with self.subTest(raw=raw[:60]):
                reply = run_cli(raw)
                self.assertEqual((reply.returncode, reply.stderr), (2, b""))
                out = json.loads(reply.stdout)
                self.assertEqual(out["error"], "invalid_input")
                self.assertNotIn("patch_status", out)


if __name__ == "__main__":
    unittest.main()
