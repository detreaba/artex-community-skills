import json
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]


def check(suffix, version, number, source="connected_server", origin="upstream"):
    data = json.loads((ROOT / "examples/pass.json").read_text())
    data["advisory"] = "CVE-2026-" + suffix
    data["evidence"].update(server_version=version, server_version_num=number, source=source, origin=origin)
    result = subprocess.run([sys.executable, "-ISB", str(ROOT / "scripts/check.py")],
                            input=json.dumps(data), text=True, capture_output=True, check=True)
    return json.loads(result.stdout)


class BackendTests(unittest.TestCase):
    def test_grok_peer_cases(self):
        # Grok's nine independent examples, replayed through the public checker.
        for suffix, version, number, source, origin, expected in (
            ("116316", "14.24", 140024, "connected_server", "upstream", "affected_version"),
            ("116316", "14.25", 140025, "connected_server", "upstream", "vendor_fix_present"),
            ("116310", "16.16", 160016, "connected_server", "upstream", "outside_affected_range"),
            ("116310", "17.11", 170011, "connected_server", "upstream", "affected_version"),
            ("116328", "15.20", 150020, "connected_server", "upstream", "outside_affected_range"),
            ("116328", "19.0", 190000, "connected_server", "upstream", "unknown"),
            ("120145", "16.16", 160015, "connected_server", "upstream", "unknown"),
            ("120145", "17.12", 170012, "client_only", "upstream", "unknown"),
            ("120145", "18.7", 180007, "connected_server", "downstream", "unknown"),
        ):
            with self.subTest(cve=suffix, version=version, source=source):
                row = check(suffix, version, number, source, origin)
                self.assertEqual((row["patch_status"], row["applicability"]), (expected, "unknown"))

    def test_all_documented_major_boundaries(self):
        for suffix, starts in (("116316", 14), ("120145", 14), ("116310", 17), ("116328", 16)):
            for major, cutoff in ((14, 25), (15, 20), (16, 16), (17, 12), (18, 7)):
                for minor in (cutoff - 1, cutoff):
                    with self.subTest(cve=suffix, major=major, minor=minor):
                        row = check(suffix, f"{major}.{minor}", str(major * 10000 + minor))
                        if major < starts:
                            self.assertEqual((row["patch_status"], row["first_fixed_on_branch"]), ("outside_affected_range", None))
                        else:
                            self.assertEqual(row["patch_status"], "affected_version" if minor < cutoff else "vendor_fix_present")
                            self.assertEqual(row["first_fixed_on_branch"], f"{major}.{cutoff}")

    def test_missing_prerelease_and_noncanonical_versions(self):
        for version, number in (("16.16", None), ("16.16", True), ("16.16", "0160016"),
                                ("16.16", 160016.0), ("16.16-rc1", 160016), (None, 160016),
                                ("13.20", 130020), ("16.16 (local build)", 160016)):
            with self.subTest(version=version, number=number):
                self.assertEqual(check("116316", version, number)["patch_status"], "unknown")
