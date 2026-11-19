"""Offline regressions for the OSV package matcher: version ordering, OSV evaluation, coverage and evidence binding."""
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[1]
CHECK = ROOT / "scripts" / "check.py"
_spec = importlib.util.spec_from_file_location("package_advisory_check", CHECK)
checker = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(checker)


def rec(rid, eco, name, *ranges, versions=None, **extra):
    entry = {"package": {"ecosystem": eco, "name": name}}
    if ranges:
        entry["ranges"] = [{"type": t, "events": ev} for t, ev in ranges]
    if versions is not None:
        entry["versions"] = versions
    return {"id": rid, "modified": "2026-11-01T00:00:00Z", "affected": [entry], **extra}


SEMVER, ECO = "SEMVER", "ECOSYSTEM"
ADVISORIES = [
    rec("T-NPM-1", "npm", "alpha", (SEMVER, [{"introduced": "0"}, {"fixed": "1.0.2"}]), aliases=["CVE-2026-0001"]),
    rec("T-NPM-2", "npm", "beta", (SEMVER, [{"introduced": "1.0.0"}, {"fixed": "1.0.2"},
                                            {"introduced": "3.0.0"}, {"fixed": "3.2.5"}])),
    rec("T-NPM-3", "npm", "gamma", (SEMVER, [{"introduced": "0"}, {"last_affected": "2.1.4"}])),
    rec("MAL-T-1", "npm", "nu", (SEMVER, [{"introduced": "4.1.1"}, {"last_affected": "4.1.2"}]), versions=["4.1.1", "4.1.2"]),
    rec("T-NPM-6", "npm", "zeta", ("GIT", [{"introduced": "0"}, {"fixed": "0123456789abcdef0123456789abcdef01234567"}]),
        versions=["1.0.0"]),
    rec("T-NPM-7", "npm", "eta", (SEMVER, [{"introduced": "0"}]), withdrawn="2026-11-02T00:00:00Z"),
    rec("T-NPM-8", "npm", "theta", (ECO, [{"introduced": "6.0"}])),
    rec("T-NPM-9", "npm", "iota", (SEMVER, [{"introduced": "1.0.0"}, {"fixed": "1.0.0"}])),
    rec("T-NPM-10", "npm", "kappa", (SEMVER, [{"introduced": "0"}, {"limit": "2.0.0"}])),
    rec("T-PKG-1", "Packagist", "acme/http", (ECO, [{"introduced": "0"}, {"fixed": "5.4.56"}]),
        (ECO, [{"introduced": "6.0.0"}, {"fixed": "6.4.50"}]), (ECO, [{"introduced": "7.0.0"}, {"fixed": "7.4.23"}])),
    rec("T-PKG-2", "Packagist:https://packages.drupal.org/8", "drupal/foo", (ECO, [{"introduced": "0"}, {"fixed": "1.35.0"}])),
    rec("T-PKG-4", "Packagist", "acme/rc", (ECO, [{"introduced": "0"}, {"fixed": "2.0.0-RC2"}])),
    rec("DEBIAN-SYNTHETIC-1", "Debian:12", "nginx", (ECO, [{"introduced": "0"}, {"fixed": "1.22.1-9+deb12u2"}]), upstream=["CVE-2026-0002"]),
    rec("DEBIAN-SYNTHETIC-3", "Debian:11", "nginx", (ECO, [{"introduced": "0"}, {"fixed": "9.9-1"}])),
]
KEV = {"catalogVersion": "test", "vulnerabilities": [{"cveID": "CVE-2026-0001", "dateAdded": "2026-01-02"},
                                                    {"cveID": "CVE-2026-0002", "dateAdded": "2026-02-03"}]}


def request(packages, covers=("npm", "Packagist", "Debian"), advisories=None, verified=True, kev=True):
    req = {"inventory": {"asset": "demo-site", "build": "build-1", "ref": "inventory-1",
                         "deployment_verified": verified, "packages": packages}}
    req["snapshot"] = {"label": "tests", "covers": list(covers),
                       "advisories": ADVISORIES if advisories is None else advisories}
    if kev:
        req["kev"] = KEV
    return req


def pkg(eco, name, version, source=True):
    item = {"ecosystem": eco, "name": name, "version": version}
    if eco.startswith("Debian") and source:
        item["source_package"] = True
    return item


class PackageAdvisoryTests(unittest.TestCase):
    def run_cli(self, raw, *args):
        cmd = [sys.executable, "-ISB", str(CHECK), *args]
        result = subprocess.run(cmd, input=raw, capture_output=True, timeout=60)
        self.assertEqual(result.stderr, b"")
        return result.returncode, json.loads(result.stdout)

    def status(self, data, *args):
        code, out = self.run_cli(json.dumps(data).encode(), *args)
        self.assertEqual(code, 0, out)
        return out

    def one(self, eco, name, version, **kwargs):
        return self.status(request([pkg(eco, name, version)], **kwargs))["packages"][0]

    def test_semver_precedence(self):
        # SemVer 2.0.0 section 11 example, then numeric precedence and build metadata.
        order = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2",
                 "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.1", "1.2.0", "1.10.0", "2.0.0"]
        keys = [checker.semver_parse(v) for v in order]
        self.assertTrue(all(k is not None for k in keys))
        self.assertEqual(keys, sorted(keys))
        self.assertEqual(checker.semver_parse("1.0.0+a"), checker.semver_parse("1.0.0+b"))
        for bad in ("01.0.0", "1.0", "v1.0.0", "1.0.0-01", "1.0.0-", "1.0.0 ", "１.0.0"):
            with self.subTest(bad=bad):
                self.assertIsNone(checker.semver_parse(bad))

    def test_debian_ordering(self):
        # Debian Policy 5.6.12: '~' sorts before everything, letters before non-letters, digits numerically.
        order = ["0.9", "1.0~~", "1.0~rc1", "1.0", "1.0-0.1", "1.0-1~bpo12+1", "1.0-1", "1.0-1+deb12u1",
                 "1.0-1+deb12u2", "1.0-1+deb12u10", "1.0a", "1.0+dfsg", "1.0.1", "1.2", "1.10", "1:0.1"]
        parsed = [checker.dpkg_parse(v) for v in order]
        self.assertTrue(all(p is not None for p in parsed))
        for a, b in zip(parsed, parsed[1:]):
            with self.subTest(a=a, b=b):
                self.assertEqual(checker.dpkg_cmp(a, b), -1)
        self.assertEqual(checker.dpkg_cmp(checker.dpkg_parse("1.0"), checker.dpkg_parse("1.0-0")), 0)
        self.assertEqual(checker.dpkg_cmp(checker.dpkg_parse("0:1.0-1"), checker.dpkg_parse("1.0-1")), 0)
        for bad in ("", "abc", "1.0-", "a:1.0", "1.0 1", "1.0_1", "-1"):
            with self.subTest(bad=bad):
                self.assertIsNone(checker.dpkg_parse(bad))

    @unittest.skipUnless(shutil.which("dpkg"), "dpkg is only available on Debian-based systems")
    def test_debian_ordering_matches_dpkg(self):
        versions = ["1.0", "1.0-1", "1.0-1+b1", "1.0~rc1-1", "1:0.5", "1.0+dfsg-2", "1.0a-1", "1.0.0-1", "2.0~~",
                    "2.0~", "2.0", "1.22.1-9", "1.22.1-9+deb12u2", "1.22.1-9~bpo12+1", "3.0.11-1~deb12u2", "10.0", "9.9"]
        for a in versions:
            for b in versions:
                ours = checker.dpkg_cmp(checker.dpkg_parse(a), checker.dpkg_parse(b))
                for op, want in (("lt", ours < 0), ("eq", ours == 0), ("gt", ours > 0)):
                    rc = subprocess.run(["dpkg", "--compare-versions", a, op, b]).returncode
                    with self.subTest(a=a, op=op, b=b):
                        self.assertEqual(rc == 0, want)

    def test_composer_ordering(self):
        order = ["1.0.0-alpha1", "1.0.0-beta", "1.0.0-beta0", "1.0.0-beta1", "1.0.0-beta.2", "1.0.0-RC1",
                 "1.0.0-rc2", "1.0.0", "1.0.0-p1", "1.0.1", "1.0.10", "1.1"]
        keys = [checker.composer_parse(v) for v in order]
        self.assertTrue(all(k is not None for k in keys))
        self.assertEqual(keys, sorted(keys))
        self.assertTrue(keys[3] < keys[4] < keys[5])
        for same in ("v1.2.3", "1.2.3.0", "1.2.3+build.7", "V1.2.3"):
            with self.subTest(same=same):
                self.assertEqual(checker.composer_parse(same), checker.composer_parse("1.2.3"))
        for bad in ("dev-main", "1.0.x-dev", "1.0.0-dev", "1.2.3.4.5", "latest", "1.0.0-beta-dev"):
            with self.subTest(bad=bad):
                self.assertIsNone(checker.composer_parse(bad))

    def test_osv_evaluation_semantics(self):
        for eco, name, version, want in (
            ("npm", "alpha", "1.0.1", "affected"), ("npm", "alpha", "1.0.2-rc.1", "affected"),
            ("npm", "alpha", "1.0.2", "no_matching_advisory"), ("npm", "alpha", "v1.0.0", "unknown"),
            ("npm", "beta", "0.9.9", "no_matching_advisory"), ("npm", "beta", "1.0.1", "affected"),
            ("npm", "beta", "2.5.0", "no_matching_advisory"), ("npm", "beta", "3.2.4", "affected"),
            ("npm", "gamma", "2.1.4", "affected"), ("npm", "gamma", "2.1.5", "unknown"),
            ("npm", "nu", "4.1.2", "affected"), ("npm", "nu", "4.1.3", "no_matching_advisory"),
            ("npm", "zeta", "1.0.0", "affected"), ("npm", "zeta", "1.0.5", "unknown"),
            ("npm", "eta", "1.0.0", "no_matching_advisory"), ("npm", "theta", "7.0.0", "unknown"),
            ("npm", "iota", "0.9.0", "unknown"), ("npm", "kappa", "1.9.9", "affected"),
            ("npm", "kappa", "2.0.0", "no_matching_advisory"), ("npm", "Alpha", "1.0.0", "no_matching_advisory"),
            ("Packagist", "acme/http", "v7.4.22", "affected"), ("Packagist", "ACME/HTTP", "6.4.49", "affected"),
            ("Packagist", "acme/http", "6.4.50", "no_matching_advisory"),
            ("Packagist", "acme/http", "7.4.23-beta1", "affected"),
            ("Packagist", "acme/http", "7.4.23-p1", "no_matching_advisory"), ("Packagist", "acme/http", "dev-main", "unknown"),
            ("Packagist", "drupal/foo", "1.34.0", "affected"), ("Packagist", "acme/rc", "2.0.0-rc2", "no_matching_advisory"),
            ("Debian:12", "nginx", "1.22.1-9~bpo12+1", "affected"), ("Debian:12", "nginx", "1.22.1-9+deb12u2", "no_matching_advisory"),
            ("Debian:12", "nginx", "1:1.0-1", "no_matching_advisory"), ("Debian:12", "nginx", "abc", "unknown"),
            ("Debian:bookworm", "nginx", "1.22.1-9", "unknown"), ("PyPI", "django", "5.2.18", "unknown"),
        ):
            with self.subTest(eco=eco, name=name, version=version):
                self.assertEqual(self.one(eco, name, version)["status"], want)

    def test_fixed_in_kev_and_malicious_flags(self):
        row = self.one("npm", "alpha", "1.0.1")
        self.assertEqual((row["advisories"][0]["fixed_in"], row["advisories"][0]["kev_date_added"]), (["1.0.2"], "2026-01-02"))
        row = self.one("Debian:12", "nginx", "1.22.1-9")
        self.assertEqual((row["advisories"][0]["cves"], row["advisories"][0]["kev_date_added"]), (["CVE-2026-0002"], "2026-02-03"))
        out = self.status(request([pkg("npm", "nu", "4.1.1"), pkg("npm", "alpha", "1.0.0")]))
        self.assertEqual((out["summary"]["malicious_listed"], out["summary"]["kev_listed"]), (1, 1))
        self.assertIsNone(self.one("npm", "beta", "1.0.1", kev=False)["advisories"][0]["kev_date_added"])

    def test_debian_requires_source_package_attestation(self):
        out = self.status(request([pkg("Debian:12", "nginx", "1.22.1-9+deb12u2", source=False)]))
        self.assertEqual(out["packages"][0]["status"], "unknown")

    def test_inventory_binding(self):
        base = request([pkg("npm", "alpha", "1.0.1")])
        for changes in ({"deployment_verified": False}, {"deployment_verified": "true"}, {"ref": ""}, {"asset": "bad alias"}):
            data = json.loads(json.dumps(base))
            data["inventory"].update(changes)
            with self.subTest(changes=changes):
                out = self.status(data)
                self.assertEqual((out["inventory_binding"], out["packages"][0]["status"]), ("unverified", "unknown"))

    def write_zip(self, folder, name, records, extra=None):
        path = Path(folder) / name
        with zipfile.ZipFile(path, "w") as archive:
            for i, record in enumerate(records):
                archive.writestr(f"{record['id']}-{i}.json", json.dumps(record))
            for entry, data in (extra or {}).items():
                archive.writestr(entry, data)
        return path

    def zip_status(self, packages, *specs):
        data = {"inventory": {"asset": "demo-site", "build": "build-1", "ref": "inventory-1",
                              "deployment_verified": True, "packages": packages}}
        code, out = self.run_cli(json.dumps(data).encode(), *specs)
        self.assertEqual(code, 0, out)
        return out

    def test_zip_snapshots_and_coverage(self):
        npm_records = [r for r in ADVISORIES if r["affected"][0]["package"]["ecosystem"] == "npm"]
        pkg_records = [r for r in ADVISORIES if r["affected"][0]["package"]["ecosystem"].startswith("Packagist")]
        with tempfile.TemporaryDirectory() as tmp:
            good = self.write_zip(tmp, "npm-all.zip", npm_records)
            out = self.zip_status([pkg("npm", "alpha", "1.0.1"), pkg("npm", "mu", "1.0.0")], "--osv", f"npm={good}")
            self.assertEqual([p["status"] for p in out["packages"]], ["affected", "no_matching_advisory"])
            self.assertEqual(len(out["snapshots"][0]["sha256"]), 64)
            self.assertTrue(out["snapshots"][0]["complete"])
            # The Packagist export passed as npm must not give npm coverage.
            wrong = self.write_zip(tmp, "Packagist-all.zip", pkg_records + npm_records[:1])
            out = self.zip_status([pkg("npm", "mu", "1.0.0")], "--osv", f"npm={wrong}")
            self.assertEqual(out["packages"][0]["status"], "unknown")
            # One unreadable record makes the family incomplete, but a match is still reported.
            broken = self.write_zip(tmp, "broken.zip", npm_records, extra={"bad.json": "{not json"})
            out = self.zip_status([pkg("npm", "mu", "1.0.0"), pkg("npm", "alpha", "1.0.1")], "--osv", f"npm={broken}")
            self.assertEqual([p["status"] for p in out["packages"]], ["unknown", "affected"])
            empty = self.write_zip(tmp, "empty.zip", [])
            out = self.zip_status([pkg("npm", "mu", "1.0.0")], "--osv", f"npm={empty}")
            self.assertEqual(out["packages"][0]["status"], "unknown")
            folder = Path(tmp) / "records"
            folder.mkdir()
            for record in npm_records:
                (folder / f"{record['id']}.json").write_text(json.dumps(record), encoding="utf-8")
            out = self.zip_status([pkg("npm", "beta", "3.0.0")], "--osv", f"npm={folder}")
            self.assertEqual(out["packages"][0]["status"], "affected")
            kev_file = Path(tmp) / "kev.json"
            kev_file.write_text(json.dumps(KEV), encoding="utf-8")
            out = self.zip_status([pkg("npm", "alpha", "1.0.1")], "--osv", f"npm={good}", "--kev", str(kev_file))
            self.assertEqual(out["kev"]["catalog_version"], "test")
            self.assertEqual(out["packages"][0]["advisories"][0]["kev_date_added"], "2026-01-02")

    def test_wildcard_names_and_damaged_ranges_never_read_as_clear(self):
        # Review of c867711: the OSV schema's "*" name covers every package in the ecosystem, and every
        # range must contain an introduced event (and may not mix fixed with last_affected).
        def single(rid, eco, name, events):
            return {"id": rid, "modified": "2026-11-19T00:00:00Z",
                    "affected": [{"package": {"ecosystem": eco, "name": name}, "ranges": [{"type": ECO if eco.startswith("Debian") else SEMVER, "events": events}]}]}
        lib12 = pkg("Debian:12", "training-lib", "1.0-1")
        with tempfile.TemporaryDirectory() as tmp:
            for name, family, record, package, want in (
                ("wild.zip", "Debian", single("W-1", "Debian:12", "*", [{"introduced": "0"}]), lib12, "affected"),
                ("wild-other.zip", "Debian", {"id": "DEBIAN-SYNTHETIC-W2", "modified": "2026-11-19T00:00:00Z", "affected": [
                    single("x", "Debian:11", "*", [{"introduced": "0"}])["affected"][0],
                    single("x", "Debian:12", "other-lib", [{"introduced": "0"}, {"fixed": "2.0-1"}])["affected"][0]]},
                 lib12, "no_matching_advisory"),
                ("npm-wild.zip", "npm", single("W-3", "npm", "*", [{"introduced": "0"}]), pkg("npm", "training-lib", "1.0.0"), "affected"),
                ("empty.zip", "npm", single("D-1", "npm", "training-lib", []), pkg("npm", "training-lib", "1.0.0"), "unknown"),
                ("fixed-only.zip", "npm", single("D-2", "npm", "training-lib", [{"fixed": "2.0.0"}]),
                 pkg("npm", "training-lib", "1.0.0"), "unknown"),
                ("mixed.zip", "npm", single("D-3", "npm", "training-lib", [{"introduced": "0"}, {"fixed": "2.0.0"},
                                                                         {"last_affected": "3.0.0"}]),
                 pkg("npm", "training-lib", "2.5.0"), "unknown"),
            ):
                with self.subTest(case=name):
                    archive = self.write_zip(tmp, name, [record])
                    row = self.zip_status([package], "--osv", f"{family}={archive}")["packages"][0]
                    self.assertEqual(row["status"], want)
                    if name in ("wild.zip", "npm-wild.zip"):
                        self.assertTrue(row["advisories"][0]["wildcard_package"])

    def test_composer_and_osv_packagist_orderings_must_agree(self):
        # OSV orders Packagist versions with PHP's version_compare: 8.4 < 8.4.0 and 1.10.0-alpha > 1.10.
        # When that ordering and Composer's disagree, the record is inconclusive rather than clear.
        records = [rec("O-1", "Packagist", "acme/short", (ECO, [{"introduced": "0"}, {"fixed": "8.4.0"}])),
                   rec("O-2", "Packagist", "acme/pre", (ECO, [{"introduced": "1.10"}, {"fixed": "1.10.11"}])),
                   rec("O-3", "Packagist", "acme/build", (ECO, [{"introduced": "0"}, {"fixed": "8.0.2"}]),
                       versions=["8.0.2+bedrock-1.18.10"])]
        for name, version, want in (("acme/short", "8.4", "unknown"), ("acme/short", "8.4.0", "no_matching_advisory"),
                                    ("acme/short", "8.3.9", "affected"), ("acme/pre", "1.10.0-alpha", "unknown"),
                                    ("acme/pre", "1.10.5", "affected"), ("acme/pre", "1.9.9", "no_matching_advisory"),
                                    ("acme/build", "8.0.2", "unknown"), ("acme/build", "8.0.1", "affected")):
            with self.subTest(name=name, version=version):
                self.assertEqual(self.one("Packagist", name, version, covers=("Packagist",), advisories=records)["status"], want)
        self.assertEqual(checker.php_cmp(checker.php_parts("8.4"), checker.php_parts("8.4.0")), -1)
        self.assertEqual(checker.php_cmp(checker.php_parts("4.0.0-beta"), checker.php_parts("4.0")), 1)
        self.assertEqual(checker.php_cmp(checker.php_parts("2.0.0-rc2"), checker.php_parts("2.0.0-RC2")), 0)
        self.assertEqual(checker.php_cmp(checker.php_parts("1.0.0-p1"), checker.php_parts("1.0.0")), 1)

    def test_debian_release_coverage_comes_from_tracker_records(self):
        tracked = [rec(f"DEBIAN-SYNTHETIC-T{i}", "Debian:12", f"lib{i}", (ECO, [{"introduced": "0"}, {"fixed": "1.0-1"}]))
                   for i in range(4)]
        fixed_only = rec("DSA-SYNTHETIC-1", "Debian:11", "nginx", (ECO, [{"introduced": "0"}, {"fixed": "1.18.0-6.1+deb11u3"}]))
        unscoped = rec("DEBIAN-SYNTHETIC-U1", "Debian", "zlib", (ECO, [{"introduced": "0"}, {"fixed": "1:1.3.dfsg-1"}]))
        snap = tracked + [fixed_only, unscoped]
        for eco, name, version, want in (("Debian:11", "nginx", "1.18.0-6.1+deb11u4", "unknown"),
                                         ("Debian:11", "nginx", "1.18.0-6.1+deb11u2", "affected"),
                                         ("Debian:12", "nginx", "1.22.1-9", "no_matching_advisory"),
                                         ("Debian:12", "zlib", "1:1.2.13.dfsg-1", "affected"),
                                         ("Debian", "nginx", "1.22.1-9", "unknown")):
            with self.subTest(eco=eco, name=name, version=version):
                self.assertEqual(self.one(eco, name, version, covers=("Debian",), advisories=snap)["status"], want)
        # Tracker records from a source that does not declare Debian cannot grant Debian coverage.
        with tempfile.TemporaryDirectory() as tmp:
            archive = self.write_zip(tmp, "debian11.zip", [rec("DEBIAN-SYNTHETIC-11", "Debian:11", "pkg0",
                                                              (ECO, [{"introduced": "0"}, {"fixed": "1.0-1"}]))])
            data = {"inventory": {"asset": "demo-site", "build": "build-1", "ref": "inventory-1",
                                  "deployment_verified": True, "packages": [pkg("Debian:12", "openssl", "3.0.11-1")]},
                    "snapshot": {"label": "npm-only", "covers": ["npm"], "advisories": ADVISORIES[:1] + tracked}}
            code, out = self.run_cli(json.dumps(data).encode(), "--osv", f"Debian={archive}")
            self.assertEqual((code, out["packages"][0]["status"]), (0, "unknown"))

    def test_urgency_and_inline_completeness_follow_the_matched_scope(self):
        # Grok, PR #9: one record names two releases; urgency must come from the matched Debian:12 entry.
        two_releases = {"id": "DSA-SYNTHETIC-9", "modified": "2026-11-01T00:00:00Z", "affected": [
            {"package": {"ecosystem": "Debian:11", "name": "openssl"}, "ecosystem_specific": {"urgency": "unimportant"},
             "ranges": [{"type": ECO, "events": [{"introduced": "0"}, {"fixed": "1.1.1w-0+deb11u2"}]}]},
            {"package": {"ecosystem": "Debian:12", "name": "openssl"}, "ecosystem_specific": {"urgency": "high"},
             "ranges": [{"type": ECO, "events": [{"introduced": "0"}, {"fixed": "3.0.12-1"}]}]}]}
        tracker = rec("DEBIAN-SYNTHETIC-T9", "Debian:12", "lib9", (ECO, [{"introduced": "0"}, {"fixed": "1.0-1"}]))
        row = self.one("Debian:12", "openssl", "3.0.11-1", covers=("Debian",), advisories=[two_releases, tracker])
        self.assertEqual((row["status"], row["advisories"][0]["distribution_urgency"]), ("affected", "high"))
        npm_only = [rec("N-1", "npm", "alpha", (SEMVER, [{"introduced": "0"}, {"fixed": "1.0.2"}]))]
        for covers in (("npm", "Packagist"), ("Packagist", "npm")):
            with self.subTest(covers=covers):
                out = self.status(request([pkg("Packagist", "acme/demo", "1.0.0"), pkg("npm", "alpha", "2.0.0")],
                                          covers=covers, advisories=npm_only))
                self.assertEqual({s["family"]: s["complete"] for s in out["snapshots"]}, {"npm": True, "Packagist": False})
                self.assertEqual([p["status"] for p in out["packages"]], ["unknown", "no_matching_advisory"])
        damaged = npm_only + [rec("D-9", "npm", "beta", (SEMVER, [{"fixed": "2.0.0"}]))]
        out = self.status(request([pkg("npm", "beta", "1.0.0")], covers=("npm",), advisories=damaged))
        self.assertEqual((out["snapshots"][0]["damaged_ranges"], out["snapshots"][0]["complete"]), (1, True))
        self.assertEqual(out["packages"][0]["status"], "unknown")

    def test_snapshot_without_family_or_with_invalid_record_is_incomplete(self):
        self.assertEqual(self.one("npm", "mu", "1.0.0", covers=("Packagist",))["status"], "unknown")
        broken = ADVISORIES + [{"id": 12345, "affected": "not-a-list"}]
        self.assertEqual(self.one("npm", "mu", "1.0.0", advisories=broken)["status"], "unknown")
        self.assertEqual(self.one("npm", "alpha", "1.0.1", advisories=broken)["status"], "affected")

    def test_malformed_requests_never_return_a_verdict(self):
        valid = json.dumps(request([pkg("npm", "alpha", "1.0.1")])).encode()
        for raw, args in ((b"{}", ()), (b"[]", ()), (b"\xff", ()), (valid[:-1], ()),
                          (json.dumps({"inventory": {"packages": []}}).encode(), ()),
                          (json.dumps({"inventory": {"asset": "a", "build": "b", "ref": "r", "deployment_verified": True,
                                                     "packages": [{"ecosystem": "npm", "name": "x"}]}}).encode(), ()),
                          (valid.replace(b'"covers": ["npm"', b'"covers": ["PyPI"'), ()),
                          (valid, ("--osv", "PyPI=missing.zip")), (valid, ("--osv", "npm=missing.zip")),
                          (valid, ("--kev",)), (valid, ("--other", "x")),
                          (b'{"inventory": {}, "inventory": {}}', ())):
            with self.subTest(raw=raw[:60], args=args):
                code, out = self.run_cli(raw, *args)
                self.assertEqual(code, 2)
                self.assertEqual(out["error"], "invalid_input")
                self.assertNotIn("packages", out)

    def test_documented_examples_through_cli(self):
        for example, statuses in (("gap", ["affected", "no_matching_advisory", "affected"]),
                                  ("pass", ["no_matching_advisory"] * 3), ("unknown", ["unknown"] * 3)):
            with self.subTest(example=example):
                code, out = self.run_cli((ROOT / "examples" / f"{example}.json").read_bytes())
                self.assertEqual(code, 0)
                self.assertEqual([p["status"] for p in out["packages"]], statuses)
                self.assertEqual(out["review_level"], "unreviewed")


if __name__ == "__main__":
    unittest.main()
