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
PHP_FPM = "CVE-2026-129292"
PHP_CGI = "CVE-2026-129538"
PHP_OOM = "CVE-2026-109618"
PHP_STALE = "CVE-2026-109619"
NODE = "CVE-2026-123865"
PHP_SESSION_FILES = "CVE-2026-126714"
PHP_FPM_SMUGGLING = "CVE-2026-129289"
PHP_TZ_CACHE = "CVE-2026-129496"
NOV_RCE = {PHP_SESSION_FILES: "session_files_handler_in_use", PHP_FPM_SMUGGLING: "backend_connection_reuse_enabled",
           PHP_TZ_CACHE: "php_error_log_to_file"}
PHP_SESSION_SHUTDOWN = "CVE-2026-129481"
PHP_MAGIC_BACKTRACE = "CVE-2026-129474"
PHP_SHUTDOWN_BACKTRACE = "CVE-2026-129182"
NOV_BRANCH = (PHP_SESSION_SHUTDOWN, PHP_MAGIC_BACKTRACE, PHP_SHUTDOWN_BACKTRACE)


def inventory(advisory, version, **changes):
    inv = {"asset": "portal-a", "build": "release-7", "ref": "serving-inventory-12",
           "origin": "upstream", "version": version, "serving_process_verified": True,
           "runtime": "php" if advisory in (PHP, PHP_FPM, PHP_CGI, PHP_OOM, PHP_STALE, *NOV_RCE, *NOV_BRANCH) else "node"}
    return {"advisory": advisory, "inventory": {**inv, **changes}}


def config(**conditions):
    return {"asset": "portal-a", "build": "release-7", "ref": "config-review-7", "conditions": conditions}


class RuntimePatchTests(unittest.TestCase):
    def php_cli(self, advisory, version, configuration=None, **changes):
        request = inventory(advisory, version, **changes)
        if configuration is not None:
            request["applicability"] = configuration
        run = subprocess.run([sys.executable, "-ISB", str(CHECKER)], input=json.dumps(request),
                             text=True, capture_output=True, timeout=5)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        return json.loads(run.stdout)

    def test_php_october_branch_fixes_through_cli(self):
        # Both October bulletins list the same four branch cutoffs.
        for below, fixed, above in (
            ("8.2.34", "8.2.35", "8.2.36"), ("8.3.35", "8.3.36", "8.3.37"),
            ("8.4.26", "8.4.27", "8.4.28"), ("8.5.11", "8.5.12", "8.5.13"),
        ):
            for version, status in ((below, "affected_version"), (fixed, "vendor_fix_present"),
                                    (above, "vendor_fix_present")):
                for advisory in (PHP_OOM, PHP_STALE):
                    with self.subTest(advisory=advisory, version=version):
                        row = self.php_cli(advisory, version)
                        self.assertEqual((row["patch_status"], row["first_fixed_on_branch"]), (status, fixed))
                        self.assertEqual(row["applicability"], "unknown")
        for version, fixed in (("8.3.0", "8.3.36"), ("8.5.0", "8.5.12")):
            for advisory in (PHP_OOM, PHP_STALE):
                with self.subTest(advisory=advisory, version=version):
                    row = self.php_cli(advisory, version)
                    self.assertEqual((row["patch_status"], row["first_fixed_on_branch"]), ("affected_version", fixed))

    def test_php_october_requires_a_serving_upstream_release(self):
        for version, changes in (
            ("8.1.99", {}), ("8.6.0", {}), ("8.4.27RC1", {}),
            ("8.3.6", {"origin": "distribution"}), ("8.3.36", {"origin": "custom"}),
            ("8.3.36", {"serving_process_verified": False}), ("8.3.36", {"runtime": "node"}),
        ):
            for advisory in (PHP_OOM, PHP_STALE):
                with self.subTest(advisory=advisory, version=version, changes=changes):
                    row = self.php_cli(advisory, version, **changes)
                    self.assertEqual((row["patch_status"], row["first_fixed_on_branch"]), ("unknown", None))

    def test_php_oom_web_role(self):
        for evidence, outcome, ref in (
            (config(php_serves_web_requests=True), "conditions_present", "config-review-7"),
            (config(php_serves_web_requests=False), "conditions_absent", "config-review-7"),
            (config(), "unknown", "config-review-7"),
            ({**config(php_serves_web_requests=True), "build": "different"}, "unknown", None),
        ):
            with self.subTest(evidence=evidence):
                row = self.php_cli(PHP_OOM, "8.4.26", evidence)
                self.assertEqual(row["patch_status"], "affected_version")
                self.assertEqual((row["applicability"], row["evidence_refs"]["configuration"]), (outcome, ref))

    def test_php_stale_state_needs_same_worker_across_web_requests(self):
        reused = config(php_serves_web_requests=True, worker_reused_across_requests=True)
        for evidence, outcome in (
            (reused, "conditions_present"),
            (config(php_serves_web_requests=True), "unknown"),
            (config(worker_reused_across_requests=True), "unknown"),
            (config(php_serves_web_requests=True, worker_reused_across_requests=False), "conditions_absent"),
            (config(php_serves_web_requests=False), "conditions_absent"),
            ({**reused, "build": "different"}, "unknown"),
        ):
            with self.subTest(evidence=evidence):
                row = self.php_cli(PHP_STALE, "8.5.11", evidence)
                self.assertEqual((row["patch_status"], row["applicability"]), ("affected_version", outcome))
        row = self.php_cli(PHP_STALE, "8.5.12", reused)
        self.assertEqual((row["patch_status"], row["applicability"]), ("vendor_fix_present", "conditions_present"))
        row = self.php_cli(PHP_STALE, "8.5.12", reused, serving_process_verified=False)
        self.assertEqual((row["patch_status"], row["applicability"]), ("unknown", "unknown"))

    def test_each_documented_upstream_boundary(self):
        php_boundaries = ["8.2.36", "8.3.37", "8.4.28", "8.5.13"]
        boundaries = {PHP: php_boundaries, PHP_FPM: php_boundaries, PHP_CGI: php_boundaries,
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
        for advisory, values in [(PHP, ["8.1.99", "8.7.0", "9.0.0", "8.4.28-dev", "v8.4.28", "8"]),
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

    def test_fpm_and_cgi_require_advisory_specific_configuration(self):
        required = {
            PHP_FPM: ("fpm_status_enabled", "request_metadata_reaches_pool", "full_status_rendered_as_html"),
            PHP_CGI: ("php_cgi_serves_requests", "cgi_fix_pathinfo_enabled", "affected_frontend_path_mapping"),
        }
        for advisory, names in required.items():
            enabled = dict.fromkeys(names, True)
            for flags, status in [
                (enabled, "conditions_present"),
                ({names[0]: True, names[1]: True}, "unknown"),
                ({**enabled, names[-1]: None}, "unknown"),
                ({names[0]: False}, "conditions_absent"),
            ]:
                with self.subTest(advisory=advisory, flags=flags):
                    request = {**inventory(advisory, "8.5.12"), "applicability": config(**flags)}
                    result = review(request)
                    self.assertEqual((result["patch_status"], result["applicability"]), ("affected_version", status))
            with self.subTest(advisory=advisory):
                request = {**inventory(advisory, "8.4.28"), "applicability": {**config(**enabled), "build": "elsewhere"}}
                result = review(request)
                self.assertEqual((result["patch_status"], result["applicability"]), ("vendor_fix_present", "unknown"))
                for origin, version in (("distribution", "8.5.13"), ("upstream", "8.7.0"), ("upstream", "8.5.13-rc1")):
                    self.assertEqual(review(inventory(advisory, version, origin=origin))["patch_status"], "unknown")
                with self.assertRaises(ValueError):
                    review({**inventory(advisory, "8.5.12"), "applicability": config(upload_progress_enabled=True)})

    def test_php_86_november_fixes_require_a_stable_serving_upstream_release(self):
        for advisory in (PHP, PHP_FPM, PHP_CGI):
            for version, fields, status, first in (
                ("8.6.0", {}, "vendor_fix_present", "8.6.0"),
                ("8.6.1", {}, "vendor_fix_present", "8.6.0"),
                ("8.6.0RC7", {}, "unknown", None),
                ("8.6.0", {"origin": "distro"}, "unknown", None),
                ("8.6.0", {"serving_process_verified": False}, "unknown", None),
            ):
                with self.subTest(advisory=advisory, version=version, fields=fields):
                    row = self.php_cli(advisory, version, **fields)
                    self.assertEqual((row["patch_status"], row["first_fixed_on_branch"]), (status, first))
                    self.assertIn("https://www.php.net/ChangeLog-8.php#8.6.0", row["sources"])
                    self.assertEqual(row["applicability"], "unknown")

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

    def test_november_rce_branch_cutoffs_through_cli(self):
        # GHSA-fm2m-fjf5-v3cp, GHSA-qc49-hpvq-g2w6 and GHSA-gr4f-wgx5-jpfv list the same four branch fixes;
        # the 8.6.0 ChangeLog records "Fixed GHSA-..." for each.
        for advisory in NOV_RCE:
            for below, fixed, above in (("8.2.35", "8.2.36", "8.2.40"), ("8.3.36", "8.3.37", "8.3.38"),
                                        ("8.4.27", "8.4.28", "8.4.29"), ("8.5.12", "8.5.13", "8.5.14")):
                for version, status in ((below, "affected_version"), (fixed, "vendor_fix_present"),
                                        (above, "vendor_fix_present")):
                    with self.subTest(advisory=advisory, version=version):
                        row = self.php_cli(advisory, version)
                        self.assertEqual((row["patch_status"], row["first_fixed_on_branch"]), (status, fixed))
            for version, status, fixed in (("8.2.0", "affected_version", "8.2.36"), ("8.5.0", "affected_version", "8.5.13"),
                                           ("8.6.0", "vendor_fix_present", "8.6.0"), ("8.6.1", "vendor_fix_present", "8.6.0")):
                with self.subTest(advisory=advisory, version=version):
                    row = self.php_cli(advisory, version)
                    self.assertEqual((row["patch_status"], row["first_fixed_on_branch"]), (status, fixed))
                    self.assertIn("https://www.php.net/ChangeLog-8.php#8.6.0", row["sources"])

    def test_november_rce_needs_a_reviewed_stable_upstream_line(self):
        # End-of-life 8.1 is inside the vendor's ranges with no fix; it stays unknown, as do future and test builds.
        for advisory in NOV_RCE:
            for version, changes in (("8.1.34", {}), ("7.4.33", {}), ("8.7.0", {}), ("9.0.0", {}), ("8.6.0RC7", {}),
                                     ("8.5.13RC1", {}), ("8.2.26", {"origin": "distribution"}),
                                     ("8.5.13", {"origin": "custom"}), ("8.5.13", {"serving_process_verified": False})):
                with self.subTest(advisory=advisory, version=version, changes=changes):
                    row = self.php_cli(advisory, version, **changes)
                    self.assertEqual((row["patch_status"], row["first_fixed_on_branch"]), ("unknown", None))

    def test_november_rce_conditions_are_each_necessary(self):
        for advisory, condition in NOV_RCE.items():
            for value, want in ((True, "conditions_present"), (False, "conditions_absent"), (None, "unknown")):
                with self.subTest(advisory=advisory, value=value):
                    row = self.php_cli(advisory, "8.5.12", config(**{condition: value}))
                    self.assertEqual((row["patch_status"], row["applicability"]), ("affected_version", want))
            other = dict(config(**{condition: True}), build="release-8")
            self.assertEqual(self.php_cli(advisory, "8.5.12", other)["applicability"], "unknown")
            # Configuration evidence stays independent of the patch verdict.
            self.assertEqual(self.php_cli(advisory, "8.5.13", config(**{condition: True}))["applicability"],
                             "conditions_present")

    def test_november_rce_sources_and_limitations(self):
        ghsa = {PHP_SESSION_FILES: "GHSA-fm2m-fjf5-v3cp", PHP_FPM_SMUGGLING: "GHSA-qc49-hpvq-g2w6", PHP_TZ_CACHE: "GHSA-gr4f-wgx5-jpfv"}
        phrases = {PHP_SESSION_FILES: "Other session storage is not affected", PHP_FPM_SMUGGLING: "php://input",
                   PHP_TZ_CACHE: "restarting the PHP master process and all workers"}
        for advisory in NOV_RCE:
            with self.subTest(advisory=advisory):
                row = self.php_cli(advisory, "8.5.12")
                self.assertEqual(row["sources"], ["https://github.com/php/php-src/security/advisories/" + ghsa[advisory],
                                                  "https://www.php.net/ChangeLog-8.php#8.6.0"])
                self.assertIn(phrases[advisory], row["limitations"][2])
                # A condition name from another advisory is rejected through the CLI.
                request = dict(inventory(advisory, "8.5.12"), applicability=config(node_handles_http2=True))
                run = subprocess.run([sys.executable, "-ISB", str(CHECKER)], input=json.dumps(request), text=True,
                                     capture_output=True, timeout=5)
                self.assertEqual((run.returncode, json.loads(run.stdout)["error"]), (2, "invalid_input"))

    def test_profile_without_conditions_never_reports_conditions_present(self):
        # all() over an empty tuple is true; a scoped empty record must still give unknown.
        profile = dict(checker.ADVISORIES[PHP_SESSION_FILES], conditions=())
        scope = {"asset": "portal-a", "build": "release-7"}
        self.assertEqual(checker._conditions(profile, config(), scope), ("unknown", "config-review-7"))
        with self.assertRaises(ValueError):
            checker._conditions(profile, config(session_files_handler_in_use=True), scope)

    def test_branch_limited_advisories_report_only_vendor_stated_exclusions(self):
        out, aff, fix, unk = "outside_affected_range", "affected_version", "vendor_fix_present", "unknown"
        for advisory, version, status, fixed in (
                # GHSA-g3vh-838c-65v7: "PHP 8.2 and earlier do not contain the field and are not affected."
                (PHP_SESSION_SHUTDOWN, "7.4.33", out, None), (PHP_SESSION_SHUTDOWN, "8.1.34", out, None),
                (PHP_SESSION_SHUTDOWN, "8.2.35", out, None), (PHP_SESSION_SHUTDOWN, "8.2.36", out, None),
                (PHP_SESSION_SHUTDOWN, "8.3.0", aff, "8.3.37"), (PHP_SESSION_SHUTDOWN, "8.3.36", aff, "8.3.37"),
                (PHP_SESSION_SHUTDOWN, "8.3.37", fix, "8.3.37"), (PHP_SESSION_SHUTDOWN, "8.4.27", aff, "8.4.28"),
                (PHP_SESSION_SHUTDOWN, "8.5.12", aff, "8.5.13"), (PHP_SESSION_SHUTDOWN, "8.6.0", fix, "8.6.0"),
                (PHP_SESSION_SHUTDOWN, "9.0.0", unk, None),
                # GHSA-8mjj-2r7p-4hg2 names 8.2 to 8.4 only, so 8.1 and older stay unknown.
                (PHP_MAGIC_BACKTRACE, "7.4.33", unk, None), (PHP_MAGIC_BACKTRACE, "8.1.34", unk, None),
                (PHP_MAGIC_BACKTRACE, "8.2.0", out, None), (PHP_MAGIC_BACKTRACE, "8.3.36", out, None),
                (PHP_MAGIC_BACKTRACE, "8.4.28", out, None), (PHP_MAGIC_BACKTRACE, "8.5.0", aff, "8.5.13"),
                (PHP_MAGIC_BACKTRACE, "8.5.12", aff, "8.5.13"), (PHP_MAGIC_BACKTRACE, "8.5.13", fix, "8.5.13"),
                (PHP_MAGIC_BACKTRACE, "8.6.0", fix, "8.6.0"),
                # GHSA-2fjv-p558-g82m: "PHP 8.4 and earlier do not contain the global and are not affected."
                (PHP_SHUTDOWN_BACKTRACE, "8.1.34", out, None), (PHP_SHUTDOWN_BACKTRACE, "8.4.27", out, None),
                (PHP_SHUTDOWN_BACKTRACE, "8.5.12", aff, "8.5.13"), (PHP_SHUTDOWN_BACKTRACE, "8.5.13", fix, "8.5.13"),
                (PHP_SHUTDOWN_BACKTRACE, "8.6.0", fix, "8.6.0"), (PHP_SHUTDOWN_BACKTRACE, "8.7.0", unk, None),
                # Codex, #43: an exclusion needs a release in PHP's release index. 6.x, 7.5, 8.1.35 and the index's
                # gaps were never published; later patches on a supported branch stay covered.
                (PHP_SESSION_SHUTDOWN, "6.0.0", unk, None), (PHP_SESSION_SHUTDOWN, "7.5.0", unk, None),
                (PHP_SESSION_SHUTDOWN, "8.1.35", unk, None), (PHP_SESSION_SHUTDOWN, "5.2.7", unk, None),
                (PHP_SESSION_SHUTDOWN, "7.4.17", unk, None), (PHP_SESSION_SHUTDOWN, "8.0.4", unk, None),
                (PHP_SESSION_SHUTDOWN, "5.2.17", out, None), (PHP_SESSION_SHUTDOWN, "8.2.37", out, None),
                (PHP_MAGIC_BACKTRACE, "8.4.0", unk, None), (PHP_MAGIC_BACKTRACE, "8.3.18", unk, None),
                (PHP_MAGIC_BACKTRACE, "8.4.9", unk, None), (PHP_MAGIC_BACKTRACE, "8.4.1", out, None),
                (PHP_MAGIC_BACKTRACE, "8.4.29", out, None),
                (PHP_SHUTDOWN_BACKTRACE, "6.0.0", unk, None), (PHP_SHUTDOWN_BACKTRACE, "8.1.35", unk, None),
                (PHP_SHUTDOWN_BACKTRACE, "8.3.34", unk, None), (PHP_SHUTDOWN_BACKTRACE, "8.4.0", unk, None),
                (PHP_SHUTDOWN_BACKTRACE, "8.3.35", out, None), (PHP_SHUTDOWN_BACKTRACE, "8.4.29", out, None)):
            with self.subTest(advisory=advisory, version=version):
                row = self.php_cli(advisory, version)
                self.assertEqual((row["patch_status"], row["first_fixed_on_branch"]), (status, fixed))
                if status == out:
                    self.assertEqual(row["patch_reason"], checker.ADVISORIES[advisory]["outside_reason"])
        reason = self.php_cli(PHP_MAGIC_BACKTRACE, "8.4.27")["patch_reason"]
        self.assertIn("no known remote trigger", reason)
        self.assertNotIn("not affected", reason)
        self.assertIn("release index", self.php_cli(PHP_SESSION_SHUTDOWN, "8.1.35")["patch_reason"])

    def test_exclusions_need_a_verified_stable_upstream_release(self):
        for advisory in NOV_BRANCH:
            for version, changes in (("8.4.27", {"origin": "distribution"}), ("8.4.27", {"origin": "custom"}),
                                     ("8.4.27", {"serving_process_verified": False}), ("8.4.0RC1", {}),
                                     ("8.6.0RC7", {})):
                with self.subTest(advisory=advisory, version=version, changes=changes):
                    row = self.php_cli(advisory, version, **changes)
                    self.assertEqual((row["patch_status"], row["first_fixed_on_branch"]), ("unknown", None))

    def test_branch_limited_configuration_evidence(self):
        # CVE-2026-129481 documents no necessary configuration, so even a scoped empty record gives unknown.
        self.assertEqual(self.php_cli(PHP_SESSION_SHUTDOWN, "8.5.12", config())["applicability"], "unknown")
        with self.assertRaises(ValueError):
            review(dict(inventory(PHP_SESSION_SHUTDOWN, "8.5.12"), applicability=config(session_files_handler_in_use=True)))
        both = ("fatal_error_backtraces_enabled", "exception_args_included")
        for flags, want in (({both[0]: True, both[1]: True}, "conditions_present"),
                            ({both[0]: True, both[1]: False}, "conditions_absent"),
                            ({both[0]: False, both[1]: None}, "conditions_absent"),
                            ({both[0]: True, both[1]: None}, "unknown")):
            with self.subTest(flags=flags):
                self.assertEqual(self.php_cli(PHP_MAGIC_BACKTRACE, "8.5.12", config(**flags))["applicability"], want)
        for value, want in ((True, "conditions_present"), (False, "conditions_absent"), (None, "unknown")):
            row = self.php_cli(PHP_SHUTDOWN_BACKTRACE, "8.5.12", config(fatal_error_backtraces_enabled=value))
            self.assertEqual(row["applicability"], want)
        # Configuration is reported beside an exclusion, as framework-patch-review does.
        row = self.php_cli(PHP_MAGIC_BACKTRACE, "8.4.27", config(**{both[0]: True, both[1]: True}))
        self.assertEqual((row["patch_status"], row["applicability"]), ("outside_affected_range", "conditions_present"))

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
