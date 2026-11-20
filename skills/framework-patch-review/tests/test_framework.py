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
DRUPAL = "CVE-2026-132165"
DRUPAL_018 = "CVE-2026-132166"
LIVEWIRE = "CVE-2025-54068"
CRAFT_PHP = "CVE-2024-56145"
CRAFT_KEY = "CVE-2025-23209"
CRAFT_CORE = "CVE-2025-32432"
PACKAGES = {
    CRAFT_PHP: ("composer", "craftcms/cms"),
    CRAFT_KEY: ("composer", "craftcms/cms"),
    CRAFT_CORE: ("composer", "craftcms/cms"),
    LIVEWIRE: ("composer", "livewire/livewire"),
    CACHE_BINARY: ("npm", "next"),
    CACHE_NESTED: ("npm", "next"),
    SYMFONY: ("composer", "symfony/http-foundation"),
    DJANGO_CACHE: ("pypi", "Django"),
    DJANGO_ADMIN: ("pypi", "Django"),
    DRUPAL: ("composer", "drupal/core"),
    DRUPAL_018: ("composer", "drupal/core"),
}


def deployment(advisory, version, **fields):
    ecosystem, package = PACKAGES[advisory]
    inventory = {"asset": "demo-portal", "build": "release-70", "ref": "image-inventory-70",
                 "ecosystem": ecosystem, "package": package, "version": version,
                 "origin": "upstream", "deployment_verified": True}
    if package == "drupal/core":
        inventory["serving_core_version"] = version
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
        # Expected cutoffs are transcribed from the respective maintainers' release notices.
        for cve, boundaries in (
            (DRUPAL, ("10.6.22", "11.3.22", "11.4.13")),
            (DRUPAL_018, ("10.6.22", "11.3.22", "11.4.13")),
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

    def test_craft_server_package_and_fix_boundaries(self):
        for advisory, last, first in (
            (CRAFT_PHP, "3.9.13", "3.9.14"), (CRAFT_PHP, "4.13.1.1", "4.13.2"),
            (CRAFT_PHP, "5.5.1.1", "5.5.2"), (CRAFT_CORE, "3.9.14", "3.9.15"),
            (CRAFT_CORE, "4.14.14", "4.14.15"), (CRAFT_CORE, "5.6.16", "5.6.17"),
            (CRAFT_KEY, "4.13.7", "4.13.8"), (CRAFT_KEY, "5.5.4", "5.5.8"),
        ):
            for tag, expected in ((last, "affected_version"), ("v" + first, "vendor_fix_present")):
                with self.subTest(advisory=advisory, tag=tag):
                    row = self.check(deployment(advisory, tag))
                    self.assertEqual((row["patch_status"], row["first_fixed_in_range"], row["version"]),
                                     (expected, first, tag.removeprefix("v")))

    def test_craft_initial_release_candidates_unpublished_versions_and_advisory_gap(self):
        for advisory, tag, want in (
            (CRAFT_PHP, "3.0.0-RC17.1", "unknown"), (CRAFT_CORE, "3.0.0-RC17.1", "affected_version"),
            (CRAFT_PHP, "4.0.0-RC1", "affected_version"), (CRAFT_KEY, "5.0.0-RC1", "affected_version"),
            (CRAFT_KEY, "3.0.0-RC1", "unknown"), (CRAFT_KEY, "3.9.14", "unknown"), (CRAFT_KEY, "5.5.6.2", "unknown"),
            (CRAFT_PHP, "4.0.0-beta.1", "unknown"), (CRAFT_CORE, "6.0.0", "unknown"),
        ):
            with self.subTest(advisory=advisory, tag=tag):
                self.assertEqual(self.check(deployment(advisory, tag))["patch_status"], want)
        for tag in ("5.5.5", "5.5.6", "5.5.6.1", "5.5.7"):
            row = self.check(deployment(CRAFT_KEY, tag))
            self.assertEqual((row["patch_status"], row["first_fixed_in_range"], row["version"]), ("unknown", None, tag))
            self.assertIn("5.5.8", row["patch_reason"])

    def test_craft_confirmed_incident_and_serving_settings(self):
        for advisory, flag, value, expected in (
            (CRAFT_KEY, "active_craft_key_compromise_confirmed", True, "conditions_present"),
            (CRAFT_KEY, "active_craft_key_compromise_confirmed", False, "unknown"),
            (CRAFT_KEY, "active_craft_key_compromise_confirmed", None, "unknown"),
            (CRAFT_PHP, "php_register_argc_argv_enabled", True, "conditions_present"),
            (CRAFT_PHP, "php_register_argc_argv_enabled", False, "conditions_absent"),
        ):
            data = deployment(advisory, "5.5.1.1")
            cfg = configuration(**{flag: value})
            with self.subTest(advisory=advisory, flag=value):
                row = self.check({**data, "applicability": cfg})
                self.assertEqual((row["patch_status"], row["applicability"]), ("affected_version", expected))
                old = self.check({**data, "applicability": {**cfg, "build": "old-release"}})
                self.assertEqual(old["applicability"], "unknown")
                self.assertIsNone(old["evidence_refs"]["configuration"])
        for fields in ({"package": "craftcms/craft"}, {"package": "craftcms/security-patches"},
                       {"origin": "distribution"}, {"origin": "custom"}, {"deployment_verified": False}):
            with self.subTest(fields=fields):
                row = self.check(deployment(CRAFT_CORE, "5.6.17", **fields))
                self.assertEqual((row["patch_status"], row["first_fixed_in_range"]), ("unknown", None))

    def test_craft_packaged_examples(self):
        for advisory, patch, feature in (
            (CRAFT_PHP, "vendor_fix_present", "conditions_absent"),
            (CRAFT_KEY, "unknown", "conditions_present"),
            (CRAFT_CORE, "affected_version", "unknown"),
        ):
            sample = json.loads((ROOT / "examples" / f"{advisory}.json").read_bytes())
            row = self.check(sample)
            self.assertEqual((row["patch_status"], row["applicability"]), (patch, feature))

    def test_livewire_published_releases_and_fix_boundary(self):
        for versions, verdict, first_fix in (
            (("v3.0.0-beta.1", "3.0.0-beta.11", "3.0.0", "3.6.2", "3.6.3"), "affected_version", "3.6.4"),
            (("v3.6.4", "3.7.0"), "vendor_fix_present", "3.6.4"),
            (("0.0.1", "1.0.0", "2.12.8"), "outside_affected_range", None),
            (("3.0.0-beta.12", "3.7.0-beta.1", "3.6.5", "2.99.0", "v4.0.0", "4.4.8", "5.0.0", "^3.6.4"), "unknown", None),
        ):
            for version in versions:
                with self.subTest(version=version):
                    row = self.check(deployment(LIVEWIRE, version))
                    self.assertEqual((row["patch_status"], row["first_fixed_in_range"]), (verdict, first_fix))

    def test_livewire_requires_installed_upstream_package(self):
        for fields in ({"origin": "custom"}, {"origin": "distribution"}, {"deployment_verified": False},
                       {"package": "laravel/framework"}, {"ecosystem": "npm"}, {"ref": ""}):
            with self.subTest(fields=fields):
                row = self.check(deployment(LIVEWIRE, "3.6.4", **fields))
                self.assertEqual((row["patch_status"], row["first_fixed_in_range"]), ("unknown", None))

    def test_livewire_scope_and_undisclosed_configuration(self):
        sample = json.loads((ROOT / "examples" / f"{LIVEWIRE}.json").read_bytes())
        self.assertEqual(self.check(sample)["version"], "3.6.3")
        for value, same_build, expected in (
            (True, True, "unknown"), (False, True, "conditions_absent"),
            (False, False, "unknown"), (None, True, "unknown"),
        ):
            with self.subTest(value=value, same_build=same_build):
                config = dict(sample["applicability"], conditions={"livewire_component_mounted": value})
                if not same_build:
                    config["build"] = "another-release"
                row = self.check({**sample, "applicability": config})
                self.assertEqual((row["patch_status"], row["first_fixed_in_range"], row["applicability"]),
                                 ("affected_version", "3.6.4", expected))
                self.assertEqual(row["evidence_refs"]["configuration"], config["ref"] if same_build else None)

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

    def test_drupal_reviewed_release_lines_and_legacy_upgrades(self):
        for version, expected, first_fix in (
            ("8.9.20", "affected_version", "10.6.22"),
            ("9.5.11", "affected_version", "10.6.22"),
            ("10.5.0", "affected_version", "10.6.22"),
            ("11.2.0", "affected_version", "11.3.22"),
            ("11.3.22", "vendor_fix_present", "11.3.22"),
            ("11.4.0", "affected_version", "11.4.13"),
            ("11.4.12", "affected_version", "11.4.13"),
            ("7.1.0", "unknown", None), ("10.7.0", "unknown", None), ("11.5.0", "unknown", None),
            ("11.4.12-dev", "unknown", None), ("11.4.13-rc1", "unknown", None),
        ):
            for advisory in (DRUPAL, DRUPAL_018):
                with self.subTest(advisory=advisory, version=version):
                    row = self.check(deployment(advisory, version))
                    self.assertEqual((row["patch_status"], row["first_fixed_in_range"]), (expected, first_fix))

    def test_drupal_patch_requires_consistent_serving_package_evidence(self):
        for fields in (
            {"package": "drupal/core-recommended"}, {"package": "drupal/recommended-project"},
            {"deployment_verified": False}, {"origin": "distribution"},
            {"serving_core_version": "11.4.12"}, {"serving_core_version": "unverified"},
            {"serving_core_version": "11.4.13-dev"},
        ):
            for advisory in (DRUPAL, DRUPAL_018):
                with self.subTest(advisory=advisory, fields=fields):
                    row = self.check(deployment(advisory, "11.4.13", **fields))
                    self.assertEqual((row["patch_status"], row["first_fixed_in_range"]), ("unknown", None))
        row = self.check(deployment(DRUPAL, "v11.4.13", serving_core_version="11.4.13"))
        self.assertEqual(row["patch_status"], "vendor_fix_present")

    def test_drupal_composer_metadata_alone_cannot_confirm_the_serving_code(self):
        for version in ("11.4.12", "11.4.13"):
            with self.subTest(version=version):
                evidence = deployment(DRUPAL, version, ref="composer-installed-in-running-image")
                del evidence["inventory"]["serving_core_version"]
                row = self.check(evidence)
                self.assertEqual(row["patch_status"], "unknown")
                self.assertIsNone(row["first_fixed_in_range"])
                self.assertIsNone(row["version"])
                self.assertEqual(row["version_evidence"], {"composer": version, "serving_core": None})
                if version == "11.4.12":
                    self.assertIn("falls in the affected range", row["patch_reason"])

    def test_drupal_fixed_composer_line_and_newer_affected_core_disagree(self):
        prior = deployment(DRUPAL, "11.3.22", asset="line-cross", build="b1", ref="inv-1",
                           serving_core_version="11.4.0")
        sample = json.loads((ROOT / "examples" / f"{DRUPAL_018}.json").read_bytes())
        for evidence, advisory, bulletin in ((prior, DRUPAL, "017"), (sample, DRUPAL_018, "018")):
            with self.subTest(advisory=advisory):
                row = self.check(evidence)
                self.assertEqual(row["advisory"], advisory)
                self.assertEqual(row["sources"], [f"https://www.drupal.org/sa-core-2026-{bulletin}"])
                self.assertEqual(row["patch_status"], "unknown")
                self.assertIsNone(row["first_fixed_in_range"])
                self.assertEqual(row["applicability"], "unknown")
                self.assertIsNone(row["version"])
                self.assertEqual(row["version_evidence"], {"composer": "11.3.22", "serving_core": "11.4.0"})
                self.assertIn("serving core falls in the affected range", row["patch_reason"])

    def test_drupal_names_each_affected_observation_on_disagreement(self):
        for composer, serving, origin, affected_sources in (
            ("11.4.13", "11.4.12", "upstream", {"serving core"}),
            (None, "11.4.12", "upstream", {"serving core"}),
            ("11.4.0", "11.3.22", "upstream", {"Composer package"}),
            ("11.4.0", "11.4.12", "upstream", {"Composer package", "serving core"}),
            ("11.4.13", "11.3.22", "upstream", set()),
            ("11.4.13", "11.4.12", "distribution", set()),
        ):
            with self.subTest(composer=composer, serving=serving, origin=origin):
                row = self.check(deployment(DRUPAL, composer, serving_core_version=serving, origin=origin))
                self.assertEqual((row["patch_status"], row["first_fixed_in_range"], row["version"]),
                                 ("unknown", None, None))
                self.assertEqual(row["version_evidence"], {"composer": composer, "serving_core": serving})
                for source in ("Composer package", "serving core"):
                    self.assertEqual(f"{source} falls in the affected range" in row["patch_reason"],
                                     source in affected_sources)

    def test_drupal_packaged_example_has_no_exposure_verdict(self):
        data = json.loads((ROOT / "examples" / f"{DRUPAL}.json").read_bytes())
        inventory = data["inventory"]
        empty_review = {"asset": inventory["asset"], "build": inventory["build"], "ref": "review-11", "conditions": {}}
        for ref in (None, empty_review):
            with self.subTest(config=ref):
                req = {**data, "applicability": ref} if ref is not None else data
                row = self.check(req)
                self.assertEqual((row["patch_status"], row["first_fixed_in_range"]), ("affected_version", "11.4.13"))
                self.assertEqual(row["applicability"], "unknown")
                self.assertIsNone(row["evidence_refs"]["configuration"])

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
