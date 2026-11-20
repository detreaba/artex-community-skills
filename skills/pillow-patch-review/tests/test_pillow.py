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


# Independent raw Windows wheel digests for the synthetic worker inventory.
WINDOWS_WRAPPERS = {
    "11.0.0": "977ffeb66fb55a6ac97ed6f480f7e8868161791ce601f949877a3fe9d3ae7bff",
    "11.1.0": "977ffeb66fb55a6ac97ed6f480f7e8868161791ce601f949877a3fe9d3ae7bff",
    "11.2.1": "977ffeb66fb55a6ac97ed6f480f7e8868161791ce601f949877a3fe9d3ae7bff",
    "11.3.0": "9cbadbda237ad8036f65c83dfa4a7d9a15a7419515cb3b06f78faa5513e2b2d4",
    "12.0.0": "e6b0cdf8588b1de6ca9563f690dea36ef0c417d8dc6f7b289a405a0d7f1d15bb",
    "12.1.0": "e6b0cdf8588b1de6ca9563f690dea36ef0c417d8dc6f7b289a405a0d7f1d15bb",
    "12.1.1": "e6b0cdf8588b1de6ca9563f690dea36ef0c417d8dc6f7b289a405a0d7f1d15bb",
    "12.2.0": "e6b0cdf8588b1de6ca9563f690dea36ef0c417d8dc6f7b289a405a0d7f1d15bb",
    "12.3.0": "0effeeecadc71257d6eabcbd4cf43277ff35c6aeda0e7ba4c60ab67676bf49de",
    "13.0.0": "7da688dee7037961d3c346ef55a8dfec3a6d787b2c9093e9e6d34a2553a1f702",
}


def evidence(version):
    scope = {"asset": "training-gallery", "build": "blue", "worker": "node-3-start-21"}
    # The worker and native observations are synthetic.
    digest = hashlib.sha256(("fixture extension " + version).encode("ascii")).digest()
    wrapper = bytes.fromhex(WINDOWS_WRAPPERS.get(version, "00" * 32))
    return {
        "advisory": "CVE-2026-59205",
        "inventory": {**scope, "ref": "serving-worker", "deployment_verified": True, "origin": "upstream",
                      "version": version},
        "wheel": {"ref": "upstream-wheel", "pypi_verified": True, "name": "Pillow", "version": version,
                  "member": "PIL/_imagingcms.cp312-win_amd64.pyd",
                  "record_hash": "sha256=" + base64.urlsafe_b64encode(digest).decode("ascii").rstrip("="),
                  "wrapper_record_hash": "sha256=" + base64.urlsafe_b64encode(wrapper).decode("ascii").rstrip("=")},
        "native": {**scope, "ref": "mapped-worker-module", "binding": "mapped_file",
                   "package_dir_ref": "worker-pil", "module": "PIL._imagingcms", "sha256": digest.hex().upper()},
        "wrapper": {**scope, "ref": "worker-import", "binding": "imported_source",
                    "package_dir_ref": "worker-pil", "module": "PIL.ImageCms", "sha256": wrapper.hex().upper()},
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
                                                        "native": "mapped-worker-module", "wrapper": "worker-import"})
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
        for section in ("inventory", "wheel", "native", "wrapper"):
            data = evidence("12.2.0")
            del data[section]
            with self.subTest(missing=section):
                self.verify(data, "unknown")

    def test_immutable_image_requires_confirmed_worker_start(self):
        data = evidence("13.0.0")
        data["native"]["binding"] = "immutable_image"
        data["wrapper"]["binding"] = "immutable_image"
        for attestation in (None, False, 1, "yes"):
            with self.subTest(attestation=attestation):
                data["native"]["immutable_start_verified"] = attestation
                self.verify(data, "unknown")
        data["native"]["immutable_start_verified"] = True
        self.verify(data, "vendor_fix_present")
        data["native"]["worker"] = "old-instance"
        self.verify(data, "unknown")

    def test_imported_wrapper_must_match_the_same_worker_directory_and_wheel(self):
        for section, field, value in (
            ("wrapper", "sha256", evidence("12.2.0")["wrapper"]["sha256"]),
            ("wrapper", "sha256", "z" * 64), ("wheel", "wrapper_record_hash", None),
            ("wrapper", "binding", "path_hash"), ("wrapper", "binding", "pyc"),
            ("wrapper", "binding", "immutable_image"), ("wrapper", "asset", "other"),
            ("wrapper", "worker", "node-3-start-20"), ("wrapper", "build", "green"),
            ("wrapper", "ref", ""), ("wrapper", "module", "other.ImageCms"),
            ("wrapper", "package_dir_ref", "other-pil"), ("native", "package_dir_ref", None),
        ):
            with self.subTest(section=section, field=field, value=value):
                data = evidence("12.3.0")
                data[section][field] = value
                self.verify(data, "unknown")

    def test_distinct_members_and_release_specific_wrapper(self):
        for target, source in (("wrapper", "native"), ("native", "wrapper")):
            data = evidence("12.3.0")
            data[target]["sha256"] = data[source]["sha256"].lower()
            native_key, wrapper_key = "record_hash", "wrapper_record_hash"
            if target == "wrapper":
                data["wheel"][wrapper_key] = data["wheel"][native_key]
            else:
                data["wheel"][native_key] = data["wheel"][wrapper_key]
            self.verify(data, "unknown")
        data = evidence("12.3.0")
        old = evidence("12.2.0")
        data["wrapper"]["sha256"] = old["wrapper"]["sha256"]
        data["wheel"]["wrapper_record_hash"] = old["wheel"]["wrapper_record_hash"]
        self.verify(data, "unknown")

    def test_platform_bytes_and_import_time_limit(self):
        data = evidence("12.3.0")
        row = self.verify(data, "vendor_fix_present")
        self.assertTrue(any("import-time attestation" in s for s in row["limitations"]))
        linux = json.loads((ROOT / "examples/pass.json").read_bytes())
        data["wrapper"]["sha256"] = linux["wrapper"]["sha256"]
        data["wheel"]["wrapper_record_hash"] = linux["wheel"]["wrapper_record_hash"]
        self.verify(data, "unknown")
        self.verify(linux, "vendor_fix_present")

    def test_legacy_native_only_record_remains_readable(self):
        for version in ("12.2.0", "12.3.0"):
            data = evidence(version)
            del data["wheel"]["wrapper_record_hash"], data["native"]["package_dir_ref"], data["wrapper"]
            row = self.verify(data, "unknown")
            self.assertIn("import record", row["patch_reason"])

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
