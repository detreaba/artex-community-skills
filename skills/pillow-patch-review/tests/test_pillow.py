"""Exercise the packaged ImageCms checker with independent worker and wheel records."""
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts" / "check.py"


def evidence(version):
    scope = {"asset": "training-gallery", "build": "blue", "worker": "node-3-start-21"}
    # All bytes and references in this inventory are synthetic.
    digest = hashlib.sha256(("fixture extension " + version).encode("ascii")).digest()
    return {
        "advisory": "CVE-2026-59205",
        "inventory": {**scope, "ref": "serving-worker", "deployment_verified": True, "origin": "upstream",
                      "version": version},
        "wheel": {"ref": "upstream-wheel", "pypi_verified": True, "name": "Pillow", "version": version,
                  "member": "PIL/_imagingcms.cp312-win_amd64.pyd",
                  "record_hash": "sha256=" + base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")},
        "native": {**scope, "ref": "mapped-worker-module", "binding": "mapped_file",
                   "module": "PIL._imagingcms", "sha256": digest.hex().upper()},
    }


class PillowTests(unittest.TestCase):
    def run_checker(self, raw, expected_exit):
        run = subprocess.run([sys.executable, "-ISB", str(CHECKER)], input=raw,
                             capture_output=True, timeout=5)
        self.assertEqual(run.stderr, b"")
        self.assertEqual(run.returncode, expected_exit, run.stdout)
        return json.loads(run.stdout)

    def verify(self, data, status):
        row = self.run_checker(json.dumps(data).encode("utf-8"), 0)
        self.assertEqual(row["patch_status"], status, row)
        self.assertEqual(row["first_fixed_release"], None if status == "unknown" else "12.3.0")
        self.assertEqual(row["version"], None if status == "unknown" else data["inventory"]["version"])
        self.assertEqual(row["applicability"], "unknown")
        return row

    def test_publisher_cutoff_and_reviewed_pypi_wheels(self):
        for version in ("11.0.0", "11.1.0", "11.2.1", "11.3.0", "12.0.0", "12.1.0", "12.1.1", "12.2.0"):
            with self.subTest(version=version):
                self.verify(evidence(version), "affected_version")
        for version in ("12.3.0", "13.0.0"):
            with self.subTest(version=version):
                row = self.verify(evidence(version), "vendor_fix_present")
                self.assertEqual(row["evidence_refs"], {"inventory": "serving-worker", "wheel": "upstream-wheel",
                                                        "native": "mapped-worker-module"})
                self.assertEqual(row["scope"]["worker"], "node-3-start-21")
        for version in ("10.4.0", "11.2.0", "12.2.1", "12.3.0rc1", "12.3.0+vendor.1", "13.0.1", "14.0.0"):
            with self.subTest(version=version):
                self.verify(evidence(version), "unknown")

    def test_loaded_bytes_must_belong_to_the_wheel_and_same_worker(self):
        for section, key, value in (
            ("inventory", "build", ""), ("inventory", "deployment_verified", 1),
            ("inventory", "origin", "distribution"), ("inventory", "version", "12.2.0"),
            ("wheel", "pypi_verified", 1), ("wheel", "name", "PIL"), ("wheel", "ref", ""),
            ("wheel", "version", "12.2.0"), ("wheel", "member", "PIL/_imaging.cpython-312-linux-gnu.so"),
            ("wheel", "member", "PIL/_imagingcms.py"), ("wheel", "member", "../PIL/_imagingcms.so"),
            ("wheel", "record_hash", "sha256="),
            ("native", "sha256", evidence("12.2.0")["native"]["sha256"]),
            ("native", "sha256", "invalid"), ("native", "module", "PIL.ImageCms"),
            ("native", "build", "green"), ("native", "asset", "another-gallery"),
            ("native", "worker", "node-3-start-20"), ("native", "ref", ""),
            ("native", "binding", "installed_path"), ("native", "binding", "immutable_image"),
        ):
            with self.subTest(section=section, key=key, value=value):
                data = evidence("12.3.0")
                data[section][key] = value
                self.verify(data, "unknown")
        for section in ("inventory", "wheel", "native"):
            data = evidence("12.2.0")
            del data[section]
            with self.subTest(missing=section):
                self.verify(data, "unknown")

    def test_immutable_image_requires_confirmed_worker_start(self):
        data = evidence("13.0.0")
        data["native"]["binding"] = "immutable_image"
        for attestation in (None, False, 1, "yes"):
            with self.subTest(attestation=attestation):
                data["native"]["immutable_start_verified"] = attestation
                self.verify(data, "unknown")
        data["native"]["immutable_start_verified"] = True
        self.verify(data, "vendor_fix_present")
        data["native"]["worker"] = "old-instance"
        self.verify(data, "unknown")

    def test_bundled_examples(self):
        for fixture, outcome in (("gap", "affected_version"), ("pass", "vendor_fix_present"), ("unknown", "unknown")):
            with self.subTest(fixture=fixture):
                self.verify(json.loads((ROOT / "examples" / (fixture + ".json")).read_bytes()), outcome)

    def test_invalid_input_has_one_error_and_exit_two(self):
        for raw in (b"[]", b"{}", b'{"advisory":"other"}', b'{"a":1,"a":2}', b'{"inventory":NaN}',
                    b'{"advisory":"CVE-2026-59205","inventory":[]}', b"{}" + b" " * 16_384):
            with self.subTest(raw=raw[:40]):
                self.assertEqual(self.run_checker(raw, 2)["error"], "invalid_input")


if __name__ == "__main__":
    unittest.main()
