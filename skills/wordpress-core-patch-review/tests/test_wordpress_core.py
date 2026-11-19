"""Offline regressions for WordPress core branch fixes, vendor statements and evidence binding."""
import json
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
CHECK = ROOT / "scripts" / "check.py"
SQLI, BATCH, TEMPLATE, UPGRADE = "CVE-2026-60137", "CVE-2026-63030", "CVE-2026-87902", "CVE-2026-119977"
# First fixed release per branch, as stated in each WordPress security advisory's patched-versions table.
VENDOR_FIXES = {
    SQLI: "6.8.6 6.9.5 7.0.2",
    BATCH: "6.9.5 7.0.2",
    TEMPLATE: ("7.1.2 7.0.6 6.9.9 6.8.10 6.7.9 6.6.9 6.5.12 6.4.12 6.3.12 6.2.13 6.1.14 6.0.16 5.9.18 5.8.17 5.7.19 "
               "5.6.21 5.5.22 5.4.23 5.3.25 5.2.28 5.1.26 5.0.29 4.9.33 4.8.32 4.7.37"),
    UPGRADE: ("7.1.4 7.0.8 6.9.11 6.8.12 6.7.11 6.6.11 6.5.14 6.4.14 6.3.14 6.2.15 6.1.16 6.0.18 5.9.20 5.8.19 5.7.21 "
              "5.6.23 5.5.24 5.4.25 5.3.27 5.2.30 5.1.28 5.0.31 4.9.35 4.8.34 4.7.39"),
}


def site(advisory, version, **fields):
    inventory = {"asset": "demo-blog", "build": "release-5", "ref": "core-version-5", "version": version,
                 "origin": "upstream", "deployment_verified": True, "core_checksums_verified": True}
    return {"advisory": advisory, "inventory": {**inventory, **fields}}


def review(**conditions):
    return {"asset": "demo-blog", "build": "release-5", "ref": "theme-review-5", "conditions": conditions}


class WordPressCoreTests(unittest.TestCase):
    def run_cli(self, raw):
        result = subprocess.run([sys.executable, "-ISB", str(CHECK)], input=raw, capture_output=True, timeout=10)
        self.assertEqual(result.stderr, b"")
        return result.returncode, json.loads(result.stdout)

    def check(self, data):
        code, result = self.run_cli(json.dumps(data).encode("utf-8"))
        self.assertEqual(code, 0, result)
        return result

    def verdict(self, advisory, version, **fields):
        row = self.check(site(advisory, version, **fields))
        return row["patch_status"], row["first_fixed_in_range"]

    def test_every_vendor_branch_boundary(self):
        for cve, fixes in VENDOR_FIXES.items():
            for fix in fixes.split():
                major, minor, patch = map(int, fix.split("."))
                for version, want in ((f"{major}.{minor}.{patch - 1}", "affected_version"), (fix, "vendor_fix_present"),
                                      (f"{major}.{minor}.{patch + 1}", "vendor_fix_present"),
                                      (f"{major}.{minor}", "affected_version")):
                    with self.subTest(cve=cve, version=version):
                        self.assertEqual(self.verdict(cve, version), (want, fix))

    def test_later_branch_that_sorts_after_an_earlier_fix_stays_affected(self):
        for cve, version, fix in ((SQLI, "6.9.4", "6.9.5"), (SQLI, "7.0.1", "7.0.2"), (BATCH, "7.0.1", "7.0.2"),
                                  (TEMPLATE, "6.0.15", "6.0.16"), (UPGRADE, "7.0.7", "7.0.8")):
            with self.subTest(cve=cve, version=version):
                self.assertEqual(self.verdict(cve, version), ("affected_version", fix))

    def test_vendor_statements_beyond_the_tables(self):
        # 7.0.2 release post: 7.1 beta2 carried the fixes; 6.8 lacks the batch issue; releases before 6.8 are unaffected.
        for cve in (SQLI, BATCH):
            for version in ("7.1", "7.1.0", "7.1.4"):
                with self.subTest(cve=cve, version=version):
                    self.assertEqual(self.verdict(cve, version), ("vendor_fix_present", "7.1"))
        for cve, version in ((SQLI, "6.7.9"), (SQLI, "4.7.39"), (BATCH, "6.8.5"), (BATCH, "6.8.12"), (BATCH, "5.0")):
            with self.subTest(cve=cve, version=version):
                self.assertEqual(self.verdict(cve, version), ("outside_affected_range", None))
        # CNA record for CVE-2026-87902 covers every release below 7.1.2; branches before 4.7 got no backport.
        self.assertEqual(self.verdict(TEMPLATE, "4.6.30"), ("affected_version", "7.1.2"))
        self.assertEqual(self.verdict(TEMPLATE, "3.9"), ("affected_version", "7.1.2"))
        self.assertEqual(self.verdict(UPGRADE, "4.6.30"), ("unknown", None))

    def test_unreviewed_lines_and_non_release_spellings(self):
        for cve in VENDOR_FIXES:
            for version in ("7.2", "8.0.1", "7.1-RC1", "6.9-beta2", "7.2-alpha-61234-src", "v7.1.4", "7.1.4.1",
                            "07.1.4", " 7.1.4", "7.1.4\n", "", 714):
                with self.subTest(cve=cve, version=version):
                    self.assertEqual(self.verdict(cve, version), ("unknown", None))

    def test_clean_results_need_checksums_but_affected_ones_do_not(self):
        for changes in ({"core_checksums_verified": False}, {"core_checksums_verified": "true"}, {}):
            data = site(UPGRADE, "7.1.4", **changes)
            if not changes:
                del data["inventory"]["core_checksums_verified"]
            with self.subTest(changes=changes):
                self.assertEqual(self.check(data)["patch_status"], "unknown")
        self.assertEqual(self.verdict(SQLI, "6.7.9", core_checksums_verified=False), ("unknown", None))
        self.assertEqual(self.verdict(UPGRADE, "7.1.3", core_checksums_verified=False), ("affected_version", "7.1.4"))

    def test_deployment_binding_and_origin(self):
        for changes in ({"origin": "managed-host"}, {"origin": "Upstream"}, {"deployment_verified": False},
                        {"deployment_verified": 1}, {"ref": ""}, {"asset": "bad alias"}, {"build": None}):
            with self.subTest(changes=changes):
                self.assertEqual(self.verdict(UPGRADE, "7.1.3", **changes), ("unknown", None))

    def test_template_preconditions_are_reported_separately(self):
        both = {"theme_has_page_prefixed_directory": True, "includable_php_target_readable": True}
        for conditions, want in ((both, "conditions_present"),
                                 ({"theme_has_page_prefixed_directory": False}, "conditions_absent"),
                                 ({"includable_php_target_readable": True}, "unknown")):
            with self.subTest(conditions=conditions):
                row = self.check({**site(TEMPLATE, "6.9.8"), "applicability": review(**conditions)})
                self.assertEqual((row["patch_status"], row["applicability"]), ("affected_version", want))
        row = self.check({**site(TEMPLATE, "6.9.8"), "applicability": {**review(**both), "build": "other"}})
        self.assertEqual((row["applicability"], row["evidence_refs"]["configuration"]), ("unknown", None))
        for cve in (SQLI, BATCH, UPGRADE):
            with self.subTest(cve=cve):
                row = self.check({**site(cve, "7.0.1"), "applicability": review()})
                self.assertEqual(row["applicability"], "unknown")

    def test_kev_and_source_metadata(self):
        for cve, added in ((SQLI, "2026-07-21"), (BATCH, "2026-07-21"), (TEMPLATE, "2026-09-25"), (UPGRADE, "2026-11-03")):
            with self.subTest(cve=cve):
                row = self.check(site(cve, "7.1.4"))
                self.assertEqual(row["kev"]["date_added"], added)
                self.assertTrue(all(u.startswith("https://") for u in row["sources"]))
        self.assertEqual(self.check(site(UPGRADE, "7.1"))["version"], "7.1")
        # The vendor advisory's own publication date (GHSA-4w3m-c66w-69mg published_at 2026-10-29).
        self.assertEqual(self.check(site(UPGRADE, "7.1.4"))["published"], "2026-10-29")

    def test_malformed_requests_never_return_a_verdict(self):
        valid = json.dumps(site(UPGRADE, "7.1.3")).encode()
        for raw in (b"{}", b"[]", b'{"advisory":"CVE-2026-0000"}', b"\xff", valid + b" " * 16384,
                    json.dumps({**site(UPGRADE, "7.1.3"), "inventory": []}).encode(),
                    json.dumps({**site(UPGRADE, "7.1.3"), "extra": 1}).encode(),
                    json.dumps({**site(UPGRADE, "7.1.3"), "applicability": review(app_router=True)}).encode(),
                    json.dumps({**site(TEMPLATE, "7.1.1"),
                                "applicability": review(theme_has_page_prefixed_directory="yes")}).encode(),
                    b'{"advisory":"CVE-2026-119977","advisory":"CVE-2026-60137","inventory":{}}',
                    # Configuration evidence is validated even when the inventory gate fails.
                    json.dumps({**site(BATCH, "6.9.4", deployment_verified=False),
                                "applicability": review(theme_has_page_prefixed_directory=True)}).encode(),
                    json.dumps({**site(TEMPLATE, "6.9.4", deployment_verified=False),
                                "applicability": review(theme_has_page_prefixed_directory="yes")}).encode(),
                    # NaN and Infinity are not JSON (RFC 8259), and the body must be UTF-8.
                    valid.replace(b'"release-5"', b"NaN", 1), valid.replace(b'"release-5"', b"Infinity", 1),
                    valid.replace(b'"release-5"', b"1e999", 1), json.dumps(site(UPGRADE, "7.1.3")).encode("utf-16"),
                    valid.replace(b"core-version-5", b"core-version-\xed\xa0\x80", 1)):
            with self.subTest(raw=raw[:70]):
                code, result = self.run_cli(raw)
                self.assertEqual((code, result["error"]), (2, "invalid_input"))
                self.assertNotIn("patch_status", result)

    def test_utf8_byte_order_mark_is_accepted(self):
        # PowerShell and other Windows tools write a UTF-8 BOM; the body is still UTF-8 JSON.
        code, row = self.run_cli(b"\xef\xbb\xbf" + json.dumps(site(UPGRADE, "7.1.3")).encode())
        self.assertEqual((code, row["patch_status"]), (0, "affected_version"))
        code, row = self.run_cli(b"\xef\xbb\xbf\xef\xbb\xbf" + json.dumps(site(UPGRADE, "7.1.3")).encode())
        self.assertEqual((code, row["error"]), (2, "invalid_input"))

    def test_documented_examples_through_cli(self):
        for example, want in (("gap", ("affected_version", "conditions_present")), ("pass", ("vendor_fix_present", "unknown")),
                              ("unknown", ("unknown", "unknown"))):
            with self.subTest(example=example):
                code, row = self.run_cli((ROOT / "examples" / f"{example}.json").read_bytes())
                self.assertEqual(code, 0)
                self.assertEqual((row["patch_status"], row["applicability"]), want)


if __name__ == "__main__":
    unittest.main()
