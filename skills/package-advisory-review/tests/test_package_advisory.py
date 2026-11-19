"""Offline regressions for the OSV package matcher: version ordering, OSV evaluation, coverage and evidence binding."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
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


def patch_central(path, name, *, flags=0, method=None, size=None):
    """Rewrite one central-directory field of an entry, as a damaged or hostile export would."""
    data = bytearray(Path(path).read_bytes())
    pos = data.find(b"PK\x01\x02")
    while pos != -1:
        length = int.from_bytes(data[pos + 28:pos + 30], "little")
        if data[pos + 46:pos + 46 + length] == name.encode():
            data[pos + 8:pos + 10] = (int.from_bytes(data[pos + 8:pos + 10], "little") | flags).to_bytes(2, "little")
            if method is not None:
                data[pos + 10:pos + 12] = method.to_bytes(2, "little")
            if size is not None:
                data[pos + 24:pos + 28] = size.to_bytes(4, "little")
            Path(path).write_bytes(bytes(data))
            return
        pos = data.find(b"PK\x01\x02", pos + 4)
    raise AssertionError(f"{name} not found in {path}")


def corrupt_data(path, name):
    """Flip bytes inside an entry's compressed data."""
    data = bytearray(Path(path).read_bytes())
    pos = data.find(b"PK\x03\x04")
    while pos != -1:
        length = int.from_bytes(data[pos + 26:pos + 28], "little")
        extra = int.from_bytes(data[pos + 28:pos + 30], "little")
        if data[pos + 30:pos + 30 + length] == name.encode():
            start = pos + 30 + length + extra
            for i in range(start + 2, start + 12):
                data[i] ^= 0xFF
            Path(path).write_bytes(bytes(data))
            return
        pos = data.find(b"PK\x03\x04", pos + 4)
    raise AssertionError(f"{name} not found in {path}")


def pkg(eco, name, version, source=True):
    item = {"ecosystem": eco, "name": name, "version": version}
    if eco.startswith("Debian") and source:
        item["source_package"] = True
    return item


class PackageAdvisoryTests(unittest.TestCase):
    def run_cli(self, raw, *args, timeout=60):
        cmd = [sys.executable, "-ISB", str(CHECK), *args]
        result = subprocess.run(cmd, input=raw, capture_output=True, timeout=timeout)
        self.assertEqual(result.stderr, b"")
        return result.returncode, json.loads(result.stdout)

    def status(self, data, *args, timeout=60):
        code, out = self.run_cli(json.dumps(data).encode(), *args, timeout=timeout)
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

    def test_hostile_strings_fail_closed_in_bounded_time(self):
        # Code review of c867711: the Composer pattern backtracked exponentially, and U+017F folded to "s".
        # Run in a child with a deadline, so a regression fails quickly instead of hanging the suite.
        evil = "1.0.0-p" + "1" * 240 + "x"
        hostile = ADVISORIES + [rec("T-EVIL", "Packagist", "acme/evil", (ECO, [{"introduced": "0"}, {"fixed": evil}]))]
        start = time.monotonic()
        out = self.status(request([pkg("Packagist", "acme/http", "5.4.55"), pkg("Packagist", "acme/x", evil),
                                   pkg("Packagist", "acme/evil", "1.0.0"), pkg("Packagist", "acme/y", "1.0.0-ſtable")],
                                  advisories=hostile), timeout=20)
        self.assertLess(time.monotonic() - start, 20)
        self.assertEqual([p["status"] for p in out["packages"]], ["affected", "unknown", "unknown", "unknown"])
        start = time.monotonic()  # 24 digits took about 2 s with the exponential pattern
        self.assertIsNone(checker.composer_parse("1.0.0-p" + "1" * 24 + "x"))
        self.assertLess(time.monotonic() - start, 0.5)

    def test_output_is_strict_json_whatever_the_records_hold(self):
        odd = rec("T-ODD", "npm", "odd", (SEMVER, [{"introduced": "0"}, {"fixed": "2.0.0"}]),
                  summary={"not": "text"}, aliases=["CVE-2026-0003"])
        odd["modified"] = [[[["deep"]]]]
        odd["affected"][0]["ecosystem_specific"] = {"urgency": 5}
        kev = {"catalogVersion": {"x": 1}, "vulnerabilities": [{"cveID": "CVE-2026-0003", "dateAdded": ""},
                                                              {"cveID": "CVE-2026-0001", "dateAdded": None}]}
        data = request([pkg("npm", "odd", "1.0.0"), pkg("npm", "alpha", "1.0.0")], covers=("npm",),
                       advisories=ADVISORIES + [odd])
        data["kev"] = kev
        code, out = self.run_cli(json.dumps(data).encode())
        self.assertEqual(code, 0)
        # Record strings reach the output only in bounded form.
        long_event = rec("T-LONG", "npm", "long", (SEMVER, [{"introduced": "0"}, {"fixed": "1" * 1_000_000}]))
        long_release = rec("DEBIAN-LONG", "Debian:" + "9" * 100_000, "zlib", (ECO, [{"introduced": "0"}]))
        big = self.status(request([pkg("npm", "long", "1.0.0"), pkg("Debian:12", "zlib", "1.0-1")],
                                  covers=("npm", "Debian"), advisories=ADVISORIES + [long_event, long_release]))
        self.assertLess(len(json.dumps(big)), 20_000)
        self.assertEqual(big["packages"][0]["status"], "unknown")
        item = out["packages"][0]["advisories"][0]
        self.assertEqual((item["modified"], item["summary"], "distribution_urgency" in item), (None, "", False))
        # KEV membership, not the date, marks a listed CVE.
        self.assertEqual((item["kev_listed"], item["kev_date_added"]), (True, None))
        self.assertEqual((out["summary"]["kev_listed"], out["kev"]["catalog_version"]), (2, None))
        for raw in (b'{"inventory": NaN}', b'{"inventory": {"x": Infinity}}', b'{"inventory": {"x": 1e999}}',
                    b"\xef\xbb\xbf\xef\xbb\xbf{}", json.dumps(data).encode("utf-16")):
            with self.subTest(raw=raw[:30]):
                self.assertEqual(self.run_cli(raw)[0], 2)
        code, out = self.run_cli(b"\xef\xbb\xbf" + json.dumps(data).encode())
        self.assertEqual((code, out["packages"][1]["status"]), (0, "affected"))
        # A launcher that closes stdin gets the invalid_input object, not a traceback.
        saved, sys.stdin = sys.stdin, None
        try:
            with contextlib.redirect_stdout(io.StringIO()) as captured:
                self.assertEqual(checker.main([]), 2)
        finally:
            sys.stdin = saved
        self.assertEqual(json.loads(captured.getvalue())["error"], "invalid_input")

    def test_unreadable_export_entries_leave_the_family_incomplete(self):
        npm_records = [r for r in ADVISORIES if r["affected"][0]["package"]["ecosystem"] == "npm"]
        lodash = rec("T-LODASH", "npm", "lodash", (SEMVER, [{"introduced": "0"}]))
        packages = [pkg("npm", "lodash", "4.17.20"), pkg("npm", "alpha", "1.0.1")]
        with tempfile.TemporaryDirectory() as tmp:
            upper = self.write_zip(tmp, "upper.zip", npm_records, extra={"T-LODASH.JSON": json.dumps(lodash)})
            out = self.zip_status(packages, "--osv", f"npm={upper}")
            self.assertEqual([p["status"] for p in out["packages"]], ["affected", "affected"])
            cases = {"notes": {"extra": {"README.txt": "not a record"}},
                     "encrypted": {"patch": {"flags": 0x1}}, "method": {"patch": {"method": 99}},
                     "lying-size": {"patch": {"size": 100}}, "corrupt": {"corrupt": True}}
            for label, spec in cases.items():
                with self.subTest(case=label):
                    body = json.dumps(lodash) + " " * 3_000_000
                    path = Path(tmp) / f"{label}.zip"
                    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
                        for i, record in enumerate(npm_records):
                            archive.writestr(f"{record['id']}-{i}.json", json.dumps(record))
                        archive.writestr("lodash.json", body)
                        for entry, data in spec.get("extra", {}).items():
                            archive.writestr(entry, data)
                    if "patch" in spec:
                        patch_central(path, "lodash.json", **spec["patch"])
                    if spec.get("corrupt"):
                        corrupt_data(path, "lodash.json")
                    out = self.zip_status(packages, "--osv", f"npm={path}")
                    source = out["snapshots"][0]
                    if label == "notes":
                        self.assertEqual((source["skipped"], out["packages"][0]["status"]), (1, "affected"))
                    else:
                        self.assertEqual((source["unreadable"], out["packages"][0]["status"]), (1, "unknown"))
                    self.assertFalse(source["complete"])
                    self.assertEqual(out["packages"][1]["status"], "affected")
            folder = Path(tmp) / "records"
            folder.mkdir()
            (folder / "T-LODASH.JSON").write_text(json.dumps(lodash), encoding="utf-8")
            (folder / "notes.txt").write_text("x", encoding="utf-8")
            out = self.zip_status(packages, "--osv", f"npm={folder}")
            self.assertEqual((out["snapshots"][0]["skipped"], out["packages"][0]["status"]), (1, "affected"))
            self.assertFalse(out["snapshots"][0]["complete"])
        # An empty PATH would otherwise read the current directory as the export.
        valid = json.dumps(request(packages, covers=("npm",))).encode()
        for args in (("--osv", "npm="), ("--osv", "npm= "), ("--kev", "")):
            with self.subTest(args=args):
                self.assertEqual(self.run_cli(valid, *args)[0], 2)

    def test_newest_copy_of_an_advisory_wins_in_any_load_order(self):
        # Codex, PR #9 (GHSA-2cjh-75gp-34gc): a newer withdrawal must win whichever snapshot loads first.
        anchor = rec("ANCHOR", "npm", "anchor", (SEMVER, [{"introduced": "0"}, {"fixed": "1.0.0"}]))

        def copy(modified, fixed="2.0.0", withdrawn=None, names=("foo",)):
            record = {"id": "GHSA-dup", "modified": modified, "affected": [
                {"package": {"ecosystem": "npm", "name": n},
                 "ranges": [{"type": SEMVER, "events": [{"introduced": "0"}, {"fixed": fixed}]}]} for n in names]}
            if withdrawn is not None:
                record["withdrawn"] = withdrawn
            return record

        cases = {
            "newer withdrawal": (copy("2024-02-06T00:00:00Z"),
                                 copy("2024-02-13T00:00:00Z", withdrawn="2024-02-13T00:00:00Z"), {"foo": "no_matching_advisory"}),
            "fractional seconds": (copy("2026-11-01T00:00:00Z", fixed="1.0.0"), copy("2026-11-01T00:00:00.500Z"),
                                   {"foo": "affected"}),
            "newer copy drops a package": (copy("2026-11-01T00:00:00Z", names=("foo", "bar")),
                                           copy("2026-11-02T00:00:00Z", names=("bar",)),
                                           {"foo": "no_matching_advisory", "bar": "affected"}),
            "tie keeps the active copy": (copy("2026-11-01T00:00:00Z"),
                                          copy("2026-11-01T00:00:00Z", withdrawn="2026-11-01T00:00:00Z"), {"foo": "affected"}),
            "tie keeps the most severe": (copy("2026-11-01T00:00:00Z", fixed="1.0.0"), copy("2026-11-01T01:00:00+01:00"),
                                          {"foo": "affected"}),
        }
        with tempfile.TemporaryDirectory() as tmp:
            for label, (older, newer, want) in cases.items():
                first = self.write_zip(tmp, "first.zip", [anchor, older])
                second = self.write_zip(tmp, "second.zip", [anchor, newer])
                packages = [pkg("npm", n, "1.5.0") for n in want]
                for order in ((first, second), (second, first)):
                    with self.subTest(case=label, loaded_first=order[0].name):
                        out = self.zip_status(packages, "--osv", f"npm={order[0]}", "--osv", f"npm={order[1]}")
                        self.assertEqual({p["name"]: p["status"] for p in out["packages"]}, want)
            # The same history split between an inline snapshot and an export.
            withdrawal = self.write_zip(tmp, "withdrawal.zip", [anchor, cases["newer withdrawal"][1]])
            data = request([pkg("npm", "foo", "1.5.0")], covers=("npm",), advisories=[anchor, cases["newer withdrawal"][0]])
            out = self.status(data, "--osv", f"npm={withdrawal}")
            self.assertEqual(out["packages"][0]["status"], "no_matching_advisory")

    def test_malformed_withdrawals_leave_the_record_active(self):
        values = ["not-a-date", True, {"x": 1}, ["2026-01-01T00:00:00Z"], "false", "2026-13-01T00:00:00Z"]
        records = [dict(rec(f"W-{i}", "npm", f"w{i}", (SEMVER, [{"introduced": "0"}])), withdrawn=v)
                   for i, v in enumerate(values)]
        # No clock is read, so a well-formed withdrawal is honoured even when it is dated in the future.
        future = dict(rec("W-future", "npm", "wfuture", (SEMVER, [{"introduced": "0"}])), withdrawn="2999-01-01T00:00:00Z")
        packages = [pkg("npm", f"w{i}", "1.0.0") for i in range(len(values))] + [pkg("npm", "wfuture", "1.0.0")]
        out = self.status(request(packages, covers=("npm",), advisories=records + [future, ADVISORIES[0]]))
        self.assertEqual([p["status"] for p in out["packages"]], ["affected"] * len(values) + ["no_matching_advisory"])
        self.assertEqual((out["snapshots"][0]["withdrawn_ignored"], out["snapshots"][0]["withdrawn"]), (len(values), 1))

    def test_events_that_share_a_version(self):
        # Real shapes: 20 DRUPAL-CONTRIB ranges with introduced == last_affected, and MAL-2026-3461/3463 with two
        # fixed events at one version. Introduced == fixed stays inconclusive at every version.
        records = [rec("E-1", "Packagist", "drupal/img", (ECO, [{"introduced": "1.0.0"}, {"last_affected": "1.0.0"}])),
                   rec("MAL-E-2", "npm", "@scope/hist", (SEMVER, [{"introduced": "1.161.12"}, {"fixed": "1.161.13"},
                                                                  {"introduced": "1.161.9"}, {"fixed": "1.161.13"}]),
                       versions=["1.161.9"]),
                   rec("E-3", "npm", "iota2", (SEMVER, [{"introduced": "1.0.0"}, {"fixed": "1.0.0"}]))]
        for eco, name, version, want in (("Packagist", "drupal/img", "1.0.0", "affected"),
                                         ("Packagist", "drupal/img", "0.9.0", "no_matching_advisory"),
                                         ("Packagist", "drupal/img", "1.0.1", "unknown"),
                                         ("Packagist", "drupal/img", "2.0.0", "unknown"),
                                         ("npm", "@scope/hist", "1.161.10", "affected"),
                                         ("npm", "@scope/hist", "1.161.14", "no_matching_advisory"),
                                         ("npm", "@scope/hist", "1.100.0", "no_matching_advisory"),
                                         ("npm", "iota2", "0.9.0", "unknown"), ("npm", "iota2", "1.0.0", "unknown"),
                                         ("npm", "iota2", "1.1.0", "unknown")):
            with self.subTest(name=name, version=version):
                self.assertEqual(self.one(eco, name, version, covers=("npm", "Packagist"), advisories=records)["status"], want)

    def test_listed_versions_outside_the_syntax_are_not_ruled_out(self):
        records = [rec("L-1", "npm", "total4", versions=["12.0"]),
                   rec("L-2", "Packagist", "symfony/symfony", versions=["2.2-dev"]),
                   rec("L-3", "Packagist", "acme/odd", versions=["1.0.0~weird"])]
        for eco, name, version, want in (("npm", "total4", "12.0.0", "unknown"),
                                         ("Packagist", "symfony/symfony", "4.4.0", "no_matching_advisory"),
                                         ("Packagist", "symfony/symfony", "2.2-dev", "affected"),
                                         # An installed development version is itself outside the release
                                         # syntax, so it reads unknown rather than clear (Fable, PR #9).
                                         ("Packagist", "symfony/symfony", "2.2.x-dev", "unknown"),
                                         ("Packagist", "acme/odd", "1.0.0", "unknown")):
            with self.subTest(name=name, version=version):
                self.assertEqual(self.one(eco, name, version, covers=("npm", "Packagist"), advisories=records)["status"], want)

    def test_composer_repositories_need_their_own_records(self):
        private = rec("R-1", "Packagist:https://repo.example.com", "acme/private", (ECO, [{"introduced": "0"}, {"fixed": "2.0.0"}]))
        for advisories, eco, name, version, want in (
                (ADVISORIES, "Packagist:https://repo.example.com", "acme/other", "1.0.0", "unknown"),
                (ADVISORIES, "Packagist:", "acme/other", "1.0.0", "unknown"),
                (ADVISORIES, "Packagist:https://repo.example.com", "acme/http", "5.4.55", "affected"),
                (ADVISORIES, "Packagist:https://packages.drupal.org/8", "drupal/foo", "1.35.0", "no_matching_advisory"),
                (ADVISORIES, "Packagist:https://packages.drupal.org/8", "drupal/foo", "1.34.0", "affected"),
                (ADVISORIES + [private], "Packagist:https://repo.example.com", "acme/other", "1.0.0", "no_matching_advisory"),
                (ADVISORIES + [private], "Packagist:https://repo.example.com", "acme/private", "1.5.0", "affected")):
            with self.subTest(eco=eco, name=name, version=version, private=len(advisories) > len(ADVISORIES)):
                self.assertEqual(self.one(eco, name, version, advisories=advisories)["status"], want)

    def test_debian_source_names_follow_policy(self):
        for name, want in (("Nginx", "unknown"), ("nginx ", "unknown"), ("n", "unknown"), ("-nginx", "unknown"),
                           ("nginx", "affected")):
            with self.subTest(name=name):
                self.assertEqual(self.one("Debian:12", name, "1.22.1-9")["status"], want)

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
