"""Offline regressions from the October Tomcat release notices and measured Maven artifacts."""
import copy
import json
from pathlib import Path
import unittest

from test_tomcat import run_cli


ROOT = Path(__file__).resolve().parents[1]
REALM = "CVE-2026-101296"
HTTP2 = "CVE-2026-101356"
CATALINA = "org.apache.tomcat-catalina"
COYOTE = "org.apache.tomcat-coyote"
EMBEDDED = "org.apache.tomcat-embed-core"


def sample(advisory):
    return json.loads((ROOT / "examples" / (advisory + ".json")).read_bytes())


def modern(advisory, version, symbol):
    data = sample(advisory)
    inventory = data["inventory"]
    inventory.pop("maven_provenance", None)
    inventory.update(implementation_version=version, upstream_version=version, bundle_symbolic_name=symbol)
    return data


class OctoberTomcatTests(unittest.TestCase):
    def decision(self, data):
        result = run_cli(json.dumps(data).encode())
        self.assertEqual(result.returncode, 0, result.stdout)
        row = json.loads(result.stdout)
        self.assertEqual(row["applicability"], "unknown")
        return row["patch_status"], row["first_fixed_on_branch"], row["observed_version"]

    def test_three_http2_introduction_and_fix_boundaries(self):
        for branch, start, fix in (("9.0", 118, 123), ("10.1", 55, 61), ("11.0", 22, 27)):
            first = f"{branch}.{fix}"
            for patch, status, cutoff in ((start - 1, "outside_affected_range", None), (start, "affected_version", first),
                                          (fix - 1, "affected_version", first), (fix, "vendor_fix_present", first)):
                version = f"{branch}.{patch}"
                for symbol in (COYOTE, EMBEDDED):
                    with self.subTest(version=version, symbol=symbol):
                        self.assertEqual(self.decision(modern(HTTP2, version, symbol)), (status, cutoff, version))

    def test_realm_fix_on_each_maintained_line_and_retired_branch(self):
        for branch, fix in (("9.0", 123), ("10.1", 61), ("11.0", 27)):
            first = f"{branch}.{fix}"
            for patch, status in ((fix - 1, "affected_version"), (fix, "vendor_fix_present")):
                version = f"{branch}.{patch}"
                with self.subTest(version=version):
                    self.assertEqual(self.decision(modern(REALM, version, CATALINA)), (status, first, version))
        data = sample(REALM)
        self.assertEqual(self.decision(data), ("affected_version", None, "7.0.109"))
        del data["inventory"]["maven_provenance"]
        self.assertEqual(self.decision(data), ("unknown", None, None))

    def test_only_the_defining_class_and_published_release_establish_a_version(self):
        for advisory, wrong_bundle, wrong_class in (
            (HTTP2, CATALINA, "org.apache.coyote.http2.Http2Protocol"),
            (REALM, COYOTE, "org.apache.catalina.connector.OutputBuffer"),
        ):
            data = modern(advisory, "11.0.26", wrong_bundle)
            self.assertEqual(self.decision(data), ("unknown", None, None))
            data["inventory"].update(bundle_symbolic_name=COYOTE if advisory == HTTP2 else CATALINA, class_name=wrong_class)
            self.assertEqual(self.decision(data), ("unknown", None, None))
        for version in ("10.1.58", "11.0.28", "11.0.27-SNAPSHOT", "12.0.0"):
            self.assertEqual(self.decision(modern(HTTP2, version, COYOTE)), ("unknown", None, None))

    def test_apache_7_0_10_archive_and_exact_milestone_names(self):
        data = sample(REALM)
        inv = data["inventory"]
        inv.update(implementation_version="7.0.10", upstream_version="7.0.10")
        proof = inv.pop("maven_provenance")
        digest = "87f0e80a51897ba669693ae829a740afd8cd5f106c76137ee7e875893e7a097d"
        inv["apache_archive_provenance"] = {"ref": "signed-apache-archive", "member": "apache-tomcat-7.0.10/lib/catalina.jar",
                                           "loaded_sha256": digest, "published_sha256": digest}
        self.assertEqual(self.decision(data), ("affected_version", None, "7.0.10"))
        inv["apache_archive_provenance"]["member"] = "apache-tomcat-7.0.11/lib/catalina.jar"
        self.assertEqual(self.decision(data), ("unknown", None, None))
        del inv["apache_archive_provenance"]
        inv["maven_provenance"] = {**proof, "coordinate": "org.apache.tomcat:tomcat-catalina:7.0.10",
                                   "loaded_sha256": digest, "published_sha256": digest}
        self.assertEqual(self.decision(data), ("unknown", None, None))
        self.assertEqual(self.decision(modern(REALM, "11.0.0-M1", CATALINA)), ("affected_version", "11.0.27", "11.0.0-M1"))
        self.assertEqual(self.decision(modern(HTTP2, "11.0.0-M1", COYOTE)), ("outside_affected_range", None, "11.0.0-M1"))

    def test_independent_provenance_and_its_attestation_limit(self):
        original = sample(HTTP2)
        for changes in ({"ref": original["inventory"]["ref"]}, {"ref": None},
                        {"coordinate": "org.apache.tomcat:tomcat-catalina:10.1.60"},
                        {"loaded_sha256": "a" * 64, "published_sha256": "a" * 64}):
            data = copy.deepcopy(original)
            data["inventory"]["maven_provenance"].update(changes)
            self.assertEqual(self.decision(data), ("unknown", None, None))
        for key, value in (("instance", ""), ("origin", "distribution"), ("source", "disk_manifest")):
            data = copy.deepcopy(original)
            data["inventory"][key] = value
            self.assertEqual(self.decision(data), ("unknown", None, None))
        result = json.loads(run_cli(json.dumps(original).encode()).stdout)
        self.assertIn("operator's inventory", result["patch_reason"])
        self.assertEqual(result["evidence_refs"]["maven_provenance"], "artifact-comparison-17")


if __name__ == "__main__":
    unittest.main()
