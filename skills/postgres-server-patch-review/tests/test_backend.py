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
        # Sorted by advisory ID. Independent expectations below are transcribed
        # by PostgreSQL release line from the publisher's November 12 tables.
        advisories = (
            "116303 116304 116306 116310 116311 116312 116315 116316 116317 "
            "116321 116322 116327 116328 116329 116331 116332 116333 116335 116336 "
            "120139 120141 120142 120143 120144 120145 120146 120148 120149 120150 "
            "120152 120153 120154"
        ).split()
        for major, cutoff, excluded in (
            (14, 25, {"116310", "116312", "116322", "116328", "116329", "116333", "120142", "120144", "120152"}),
            (15, 20, {"116310", "116322", "116328", "116329", "116333", "120142", "120144", "120152"}),
            (16, 16, {"116310", "116322", "116329", "116333", "120142", "120144"}),
            (17, 12, {"116322", "116329", "120144"}),
            (18, 7, set()),
        ):
            for suffix in advisories:
                for minor in (cutoff - 1, cutoff, cutoff + 1):
                    with self.subTest(cve=suffix, major=major, minor=minor):
                        row = check(suffix, f"{major}.{minor}", str(major * 10000 + minor))
                        self.assertEqual(row["sources"], [f"https://www.postgresql.org/support/security/CVE-2026-{suffix}/"])
                        self.assertEqual(row["applicability"], "unknown")
                        if suffix in excluded:
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

    def test_plpgsql_requires_its_own_module_evidence(self):
        request = json.loads((ROOT / "examples/pass.json").read_text())
        request["advisory"] = "CVE-2026-120151"
        run = subprocess.run([sys.executable, "-ISB", str(ROOT / "scripts/check.py")],
                             input=json.dumps(request), text=True, capture_output=True)
        self.assertEqual(run.returncode, 2)
        self.assertEqual(json.loads(run.stdout)["error"], "invalid_input")
