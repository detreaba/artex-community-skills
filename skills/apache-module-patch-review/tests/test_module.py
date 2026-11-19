import json
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]


def check(cve, **observation):
    data = json.loads((ROOT / "examples/pass.json").read_text())
    data["advisory"] = cve
    data["evidence"].update(observation)
    result = subprocess.run([sys.executable, "-ISB", str(ROOT / "scripts/check.py")],
                            input=json.dumps(data), text=True, capture_output=True, check=True)
    return json.loads(result.stdout)


class ModuleTests(unittest.TestCase):
    def test_each_bundled_module_has_its_own_lower_bound(self):
        for suffix, module, before, first in (("119618", "mod_http2", "2.4.54", "2.4.55"),
                                              ("106023", "mod_md", "2.4.29", "2.4.30"),
                                              ("109163", "mod_vhost_alias", "2.4.68", "2.4.69")):
            for version, want in ((before, "outside_affected_range"), (first, "affected_version"),
                                  ("2.4.70", "affected_version"), ("2.4.71", "vendor_fix_present")):
                with self.subTest(cve=suffix, version=version):
                    row = check("CVE-2026-" + suffix, module=module, server_version=version, module_release=version)
                    self.assertEqual(row["patch_status"], want)
                    self.assertEqual(row["first_fixed_on_branch"], None if version == before else "2.4.71")
                    self.assertEqual(row["applicability"], "unknown")

    def test_separate_module_is_not_fixed_by_upgrading_the_server(self):
        for version, want in (("2.0.8", "affected_version"), ("2.0.42", "affected_version"),
                              ("2.0.43", "unknown"), ("2.0.42-vendor", "unknown")):
            with self.subTest(version=version):
                row = check("CVE-2026-119618", module_origin="standalone-mod_h2", module_release=version)
                self.assertEqual(row["patch_status"], want)
                self.assertIsNone(row["first_fixed_on_branch"])

    def test_host_or_unrelated_module_cannot_establish_a_fix(self):
        for changes in ({"source": "server_banner"}, {"module": "mod_md"}, {"module_release": "2.4.69"},
                        {"module_origin": "vendor-module"}, {"origin": "distribution"},
                        {"server_version": "2.5.0", "module_release": "2.5.0"}, {"module_release": None}):
            with self.subTest(changes=changes):
                self.assertEqual(check("CVE-2026-119618", **changes)["patch_status"], "unknown")
