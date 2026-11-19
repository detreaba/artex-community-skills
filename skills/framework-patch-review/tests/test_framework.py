"""Offline CLI regressions for published upstream release ranges and evidence binding."""
import json
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
CHECK = ROOT / "scripts" / "check.py"
CACHE_BINARY = "CVE-2026-119349"
CACHE_NESTED = "CVE-2026-119351"
SYMFONY = "CVE-2026-118514"
DJANGO_CACHE = "CVE-2026-113593"
DJANGO_ADMIN = "CVE-2026-113733"
PACKAGES = {
    CACHE_BINARY: ("npm", "next"),
    CACHE_NESTED: ("npm", "next"),
    SYMFONY: ("composer", "symfony/http-foundation"),
    DJANGO_CACHE: ("pypi", "Django"),
    DJANGO_ADMIN: ("pypi", "Django"),
}


def deployment(advisory, version, **fields):
    ecosystem, package = PACKAGES[advisory]
    inventory = {"asset": "demo-portal", "build": "release-70", "ref": "image-inventory-70",
                 "ecosystem": ecosystem, "package": package, "version": version,
                 "origin": "upstream", "deployment_verified": True}
    return {"advisory": advisory, "inventory": {**inventory, **fields}}


def configuration(**conditions):
    return {"asset": "demo-portal", "build": "release-70", "ref": "config-export-70",
            "conditions": conditions}


class FrameworkTests(unittest.TestCase):
    def run_cli(self, raw):
        cmd = [sys.executable, "-ISB", str(CHECK)]
        result = subprocess.run(cmd, input=raw, capture_output=True, timeout=5)
        self.assertEqual(result.stderr, b"")
        return result.returncode, json.loads(result.stdout)

    def check(self, data):
        code, result = self.run_cli(json.dumps(data).encode("utf-8"))
        self.assertEqual(code, 0, result)
        return result

    def test_first_fixed_release_on_every_reviewed_branch(self):
        # Source: the respective 2026-11 Django, Vercel and Symfony release notices.
        for cve, boundaries in (
            (DJANGO_CACHE, ("5.2.19", "6.0.10", "6.1.3")),
            (DJANGO_ADMIN, ("6.0.10", "6.1.3")),
            (SYMFONY, ("5.4.56", "6.4.50", "7.4.23", "8.1.11")),
            (CACHE_BINARY, ("16.4.5",)), (CACHE_NESTED, ("16.4.5",)),
        ):
            for boundary in boundaries:
                branch, patch = boundary.rsplit(".", 1)
                for offset, verdict in ((-1, "affected_version"), (0, "vendor_fix_present"),
                                        (1, "vendor_fix_present")):
                    version = f"{branch}.{int(patch) + offset}"
                    with self.subTest(cve=cve, version=version):
                        result = self.check(deployment(cve, version))
                        self.assertEqual(result["patch_status"], verdict)
                        self.assertEqual(result["first_fixed_in_range"], boundary)
                        self.assertEqual(result["applicability"], "unknown")
                        self.assertEqual(result["evidence_refs"]["inventory"], "image-inventory-70")
                        self.assertTrue(any(u.startswith("https://") for u in result["sources"]))

    def test_two_next_advisories_have_different_lower_bounds(self):
        for version, binary, nested in (
            ("15.5.29", "outside_affected_range", "outside_affected_range"),
            ("16.0.0", "affected_version", "outside_affected_range"),
            ("16.1.0", "affected_version", "outside_affected_range"),
            ("16.2.0", "affected_version", "affected_version"),
            ("17.0.0", "unknown", "unknown"),
        ):
            for cve, expected in ((CACHE_BINARY, binary), (CACHE_NESTED, nested)):
                with self.subTest(cve=cve, version=version):
                    self.assertEqual(self.check(deployment(cve, version))["patch_status"], expected)

    def test_symfony_ranges_span_minor_versions(self):
        for version in ("4.4.51", "5.3.16", "6.0.0", "6.3.12", "7.0.0", "7.3.6", "8.0.0"):
            with self.subTest(version=version):
                self.assertEqual(self.check(deployment(SYMFONY, version))["patch_status"], "affected_version")
        self.assertEqual(self.check(deployment(SYMFONY, "v7.4.23"))["patch_status"], "vendor_fix_present")
        self.assertEqual(self.check(deployment(SYMFONY, "9.0.0"))["patch_status"], "unknown")

    def test_django_branch_exclusions_and_release_spelling(self):
        self.assertEqual(self.check(deployment(DJANGO_ADMIN, "5.2.18"))["patch_status"], "outside_affected_range")
        self.assertEqual(self.check(deployment(DJANGO_CACHE, "5.2.18"))["patch_status"], "affected_version")
        self.assertEqual(self.check(deployment(DJANGO_CACHE, "5.2", package="django"))["patch_status"], "affected_version")
        for version in ("4.2.25", "6.2.0"):
            with self.subTest(version=version):
                self.assertEqual(self.check(deployment(DJANGO_CACHE, version))["patch_status"], "unknown")

    def test_deployment_identity_origin_and_exact_version(self):
        data = deployment(CACHE_BINARY, "16.4.5")
        for key in ("asset", "build", "ref", "package", "ecosystem", "version", "origin", "deployment_verified"):
            with self.subTest(missing=key):
                copy = {"advisory": CACHE_BINARY, "inventory": data["inventory"].copy()}
                del copy["inventory"][key]
                self.assertEqual(self.check(copy)["patch_status"], "unknown")
        for changes in ({"ecosystem": "pypi"}, {"package": "next-api"}, {"origin": "distro"},
                        {"deployment_verified": False}, {"version": ">=16.4.5"}, {"version": "16.4"},
                        {"version": "16.4.5-canary.1"}, {"version": "16.4.5+vendor"}, {"version": 16}):
            with self.subTest(changes=changes):
                result = self.check({**data, "inventory": {**data["inventory"], **changes}})
                self.assertEqual(result["patch_status"], "unknown")

    def test_feature_applicability_is_independent_of_patch_result(self):
        for cve, version, keys in (
            (CACHE_BINARY, "16.0.0", ["app_router", "binary_arguments_to_use_cache"]),
            (CACHE_NESTED, "16.2.0", ["cache_components", "nested_cache_reads_root_params_with_pending_promises"]),
            (DJANGO_CACHE, "5.2", ["django_page_cache_in_use", "vary_header_present"]),
            (DJANGO_ADMIN, "6.1", ["view_only_user_admin", "affected_user_model_layout"]),
            (SYMFONY, "8.1.10", ["get_rule_without_head"]),
        ):
            data = deployment(cve, version)
            for flags, want in ((dict.fromkeys(keys, True), "conditions_present"),
                                ({keys[0]: False}, "conditions_absent"),
                                (dict.fromkeys(keys[1:], True), "unknown")):
                with self.subTest(cve=cve, flags=flags):
                    result = self.check({**data, "applicability": configuration(**flags)})
                    self.assertEqual((result["patch_status"], result["applicability"]), ("affected_version", want))
                    self.assertEqual(result["evidence_refs"]["configuration"], "config-export-70")

    def test_configuration_must_match_build_and_asset(self):
        data = deployment(SYMFONY, "7.4.22")
        cfg = configuration(get_rule_without_head=True)
        for changes in ({"asset": "elsewhere"}, {"build": "another-release"}, {"ref": ""}):
            with self.subTest(changes=changes):
                result = self.check({**data, "applicability": {**cfg, **changes}})
                self.assertEqual(result["patch_status"], "affected_version")
                self.assertEqual(result["applicability"], "unknown")
                self.assertIsNone(result["evidence_refs"]["configuration"])

    def test_distribution_package_can_have_verified_feature_configuration(self):
        data = deployment(SYMFONY, "7.4.23", origin="distribution")
        result = self.check({**data, "applicability": configuration(get_rule_without_head=True)})
        self.assertEqual(result["patch_status"], "unknown")
        self.assertEqual(result["applicability"], "conditions_present")

    def test_malformed_requests_never_return_a_verdict(self):
        data = deployment(SYMFONY, "7.4.22")
        valid = json.dumps(data).encode()
        for raw in (b"{}", b"[]", b'{"advisory":"*"}', b'{"advisory":"previous",' + valid[1:],
                    valid + b" " * 16384, b"\xff",
                    json.dumps({**data, "inventory": []}).encode(),
                    json.dumps({**data, "applicability": configuration(get_rule_without_head="true")}).encode(),
                    json.dumps({**data, "applicability": configuration(app_router=True)}).encode()):
            with self.subTest(raw=raw):
                code, result = self.run_cli(raw)
                self.assertNotEqual(code, 0)
                self.assertEqual(result["error"], "invalid_input")
                self.assertNotIn("patch_status", result)

    def test_documented_examples_through_cli(self):
        for example, status in (("gap", "affected_version"), ("pass", "vendor_fix_present"), ("unknown", "unknown")):
            with self.subTest(example=example):
                code, result = self.run_cli((ROOT / "examples" / f"{example}.json").read_bytes())
                self.assertEqual(code, 0)
                self.assertEqual(result["patch_status"], status)


if __name__ == "__main__":
    unittest.main()
