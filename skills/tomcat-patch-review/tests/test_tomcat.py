"""Exercise the public CLI with independently stated release and evidence expectations."""
import json
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
ADVISORY = "CVE-2026-103119"
CATALINA = "org.apache.tomcat-catalina"
EMBEDDED = "org.apache.tomcat-embed-core"


def inventory(version, bundle=CATALINA, **changes):
    fields = {
        "asset": "portal", "build": "image-17", "instance": "jvm-3", "ref": "class-inventory-17",
        "deployment_verified": True, "origin": "upstream", "upstream_version": version,
        "source": "serving_class_manifest", "class_name": "org.apache.catalina.connector.OutputBuffer",
        "bundle_symbolic_name": bundle, "implementation_version": version,
    }
    return {"advisory": ADVISORY, "inventory": {**fields, **changes}}


def run_cli(raw):
    return subprocess.run([sys.executable, "-ISB", str(ROOT / "scripts" / "check.py")],
                          input=raw, capture_output=True, timeout=5)


class TomcatTests(unittest.TestCase):
    def result(self, request):
        run = run_cli(json.dumps(request).encode())
        self.assertEqual(run.returncode, 0, (run.stdout, run.stderr))
        self.assertEqual(run.stderr, b"")
        result = json.loads(run.stdout)
        self.assertEqual(result["advisory"], request["advisory"])
        self.assertEqual(result["applicability"], "unknown")
        return result

    def assert_unknown(self, request):
        result = self.result(request)
        self.assertEqual(result["patch_status"], "unknown")
        self.assertIsNone(result["first_fixed_on_branch"])
        self.assertIsNone(result["observed_version"])

    def test_bulletin_boundary_and_next_published_release_in_both_artifacts(self):
        for bundle in (CATALINA, EMBEDDED):
            for version, status in (("11.0.0", "affected_version"), ("11.0.26", "affected_version"),
                                    ("11.0.27", "vendor_fix_present"), ("11.0.29", "vendor_fix_present")):
                with self.subTest(bundle=bundle, version=version):
                    row = self.result(inventory(version, bundle))
                    self.assertEqual((row["patch_status"], row["first_fixed_on_branch"]), (status, "11.0.27"))
                    self.assertEqual(row["observed_version"], version)
                    self.assertEqual(row["scope"], {"asset": "portal", "build": "image-17", "instance": "jvm-3"})
                    self.assertEqual(row["evidence_refs"]["inventory"], "class-inventory-17")

    def test_release_numbers_absent_from_the_apache_archive(self):
        for patch in (16, 17, 19, 28, 30):
            with self.subTest(patch=patch):
                self.assert_unknown(inventory(f"11.0.{patch}"))
        for patch in (15, 18, 20):
            with self.subTest(patch=patch):
                self.assertEqual(self.result(inventory(f"11.0.{patch}"))["patch_status"], "affected_version")

    def test_unreviewed_lines_milestones_and_development_versions(self):
        for version in ("9.0.117", "10.1.34", "11.1.0", "12.0.0", "11.0.0-M25", "11.0.27-RC1",
                        "11.0.27-SNAPSHOT", "11.0.027", "11.0.27.0", None, 27, []):
            with self.subTest(version=version):
                self.assert_unknown(inventory(version))

    def test_scope_and_runtime_binding(self):
        for name in ("asset", "build", "instance", "ref", "origin", "upstream_version", "source", "class_name",
                     "bundle_symbolic_name", "implementation_version", "deployment_verified"):
            with self.subTest(missing=name):
                request = inventory("11.0.27")
                del request["inventory"][name]
                self.assert_unknown(request)
        for changes in ({"ref": " "}, {"deployment_verified": 1}, {"deployment_verified": False},
                        {"deployment_verified": "true"}, {"source": "pom"}, {"source": "jar_on_disk"},
                        {"source": "server_info"}, {"source": "http_header"}, {"origin": "distribution"},
                        {"origin": "custom"}, {"class_name": "org.apache.catalina.util.ServerInfo"},
                        {"bundle_symbolic_name": "org.apache.tomcat-coyote"}, {"bundle_symbolic_name": []}):
            with self.subTest(changes=changes):
                for version in ("11.0.26", "11.0.27"):
                    self.assert_unknown(inventory(version, **changes))

    def test_conflicting_loaded_manifest_and_attributed_release(self):
        for version, manifest in (("11.0.27", "11.0.26"), ("11.0.26", "11.0.27"),
                                  ("11.0.29", "11.0.27")):
            with self.subTest(version=version, manifest=manifest):
                request = inventory(version, implementation_version=manifest)
                self.assert_unknown(request)

    def test_bundled_examples_through_stdin(self):
        for name, status in (("gap", "affected_version"), ("pass", "vendor_fix_present"), ("unknown", "unknown")):
            with self.subTest(example=name):
                request = json.loads((ROOT / "examples" / f"{name}.json").read_bytes())
                self.assertEqual(self.result(request)["patch_status"], status)

    def test_default_servlet_branch_boundaries_in_both_artifacts(self):
        for bundle in (CATALINA, EMBEDDED):
            for before, fixed, after in (("9.0.98", "9.0.99", "9.0.100"),
                                          ("10.1.34", "10.1.35", "10.1.36"), ("11.0.2", "11.0.3", "11.0.4")):
                for version in (before, fixed, after):
                    with self.subTest(version=version, bundle=bundle):
                        req = inventory(version, bundle, class_name="org.apache.catalina.servlets.DefaultServlet")
                        req["advisory"] = "CVE-2025-24813"
                        result = self.result(req)
                        self.assertEqual(result["first_fixed_on_branch"], fixed)
                        self.assertEqual(result["patch_status"], "affected_version" if version == before else "vendor_fix_present")

    def test_legacy_default_servlet_needs_independent_artifact_identity(self):
        req = json.loads((ROOT / "examples/CVE-2025-24813.json").read_bytes())
        row = self.result(req)
        self.assertEqual((row["patch_status"], row["first_fixed_on_branch"]), ("affected_version", None))
        self.assertEqual(row["observed_version"], "8.5.100")
        proof = req["inventory"].pop("maven_provenance")
        self.assert_unknown(req)
        for changes in ({"coordinate": "org.apache.tomcat:tomcat-tribes:8.5.100"}, {"published_sha256": "f" * 64},
                        {"ref": ""}, {"coordinate": "org.apache.tomcat:tomcat-catalina:8.5.99"}):
            req["inventory"]["maven_provenance"] = {**proof, **changes}
            self.assert_unknown(req)
        req["inventory"]["maven_provenance"] = proof
        req["inventory"]["bundle_symbolic_name"] = CATALINA
        self.assert_unknown(req)

    def test_legacy_digest_is_pinned_to_the_exact_coordinate(self):
        req = json.loads((ROOT / "examples/CVE-2025-24813.json").read_bytes())
        proof = req["inventory"]["maven_provenance"]
        for digest in ("a" * 64, "d4d8097f87a4dcd7560e01c1878b8a0aaf365b2c9477674a10f62df83f1aa53e"):
            proof.update(loaded_sha256=digest, published_sha256=digest.upper())
            self.assert_unknown(req)
        proof["coordinate"] = "org.apache.tomcat.embed:tomcat-embed-core:8.5.100"
        row = self.result(req)
        self.assertEqual((row["patch_status"], row["first_fixed_on_branch"]), ("affected_version", None))

    def test_default_servlet_excluded_versions_and_wrong_classes(self):
        for version in ("8.5.0", "8.5.2", "9.0.1", "9.0.2", "9.0.0.M1", "9.0.103", "10.0.27", "10.1.38",
                        "11.0.19", "9.0.125", "10.1.63", "11.0.30"):
            req = inventory(version, class_name="org.apache.catalina.servlets.DefaultServlet")
            req["advisory"] = "CVE-2025-24813"
            self.assert_unknown(req)
        req = inventory("11.0.3")
        req["advisory"] = "CVE-2025-24813"
        self.assert_unknown(req)
        req["inventory"]["class_name"] = "org.apache.catalina.servlets.DefaultServlet"
        req["inventory"]["origin"] = "distribution"
        self.assert_unknown(req)

    def test_malformed_input_returns_one_json_error(self):
        for raw in (b"not json", b"\xff", b"{}", b"[]", b'{"advisory":null,"advisory":"CVE-2026-103119"}',
                    b'{"advisory":"CVE-2026-103119","inventory":[]}', b'{"advisory":"other"}',
                    b'{"advisory":"CVE-2026-103119","inventory":{"implementation_version":NaN}}',
                    b'{"advisory":"CVE-2026-103119","inventory":{"upstream_version":Infinity}}',
                    b'{"advisory":"CVE-2026-103119","inventory":{"unrecognized":"field"}}',
                    b'{"advisory":"CVE-2026-103119"}' + b" " * 16384):
            with self.subTest(raw=raw[:60]):
                run = run_cli(raw)
                self.assertEqual(run.returncode, 2)
                self.assertEqual(run.stderr, b"")
                result = json.loads(run.stdout)
                self.assertEqual(result["error"], "invalid_input")
                self.assertNotIn("patch_status", result)


if __name__ == "__main__":
    unittest.main()
