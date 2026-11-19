"""Exercise the evidence boundary and the standalone release archives."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from package_skills import build

NAMES = ("nginx-worker-patch-review", "apache-module-patch-review", "postgres-server-patch-review")


def command(skill, input_bytes):
    run = subprocess.run([sys.executable, "-ISB", str(skill / "scripts/check.py")],
                         input=input_bytes, capture_output=True, timeout=5)
    return run.returncode, json.loads(run.stdout)


class EvidenceTests(unittest.TestCase):
    def test_archives_work_outside_the_repository(self):
        with tempfile.TemporaryDirectory() as tmp:
            clone = Path(tmp) / "source"
            clone.mkdir()
            shutil.copy2(ROOT / "LICENSE", clone)
            shutil.copytree(ROOT / "shared", clone / "shared")
            for name in NAMES:
                shutil.copytree(ROOT / "skills" / name, clone / "skills" / name)
            build(clone)
            for name in NAMES:
                dest = Path(tmp) / "installed"
                with ZipFile(clone / "dist" / (name + ".zip")) as archive:
                    archive.extractall(dest)
                skill = dest / name
                for fixture, want in (("gap", "affected_version"), ("pass", "vendor_fix_present"), ("unknown", "unknown")):
                    with self.subTest(skill=name, fixture=fixture):
                        code, row = command(skill, (skill / "examples" / (fixture + ".json")).read_bytes())
                        self.assertEqual((code, row["patch_status"], row["applicability"]), (0, want, "unknown"))
                        self.assertTrue(row["evidence_ref"])
                        self.assertTrue(row["sources"][0].startswith("https://"))

    def test_scope_and_invalid_input(self):
        for name in NAMES:
            skill = ROOT / "skills" / name
            data = json.loads((skill / "examples/pass.json").read_text())
            obs = data["evidence"]
            for changes in ({"build": "stale"}, {"asset": "different"}, {"ref": ""}):
                with self.subTest(skill=name, changes=changes):
                    code, row = command(skill, json.dumps({**data, "evidence": {**obs, **changes}}).encode())
                    self.assertEqual((code, row["patch_status"], row["evidence_ref"]), (0, "unknown", None))
            valid = json.dumps(data).encode()
            for raw in (b"[]", b"null", b"\xff", valid + b" " * 16384,
                        b'{"advisory":"duplicate",' + valid[1:],
                        json.dumps({**data, "evidence": {**obs, "arbitrary": True}}).encode()):
                with self.subTest(skill=name, sample=raw[:25]):
                    code, row = command(skill, raw)
                    self.assertEqual((code, row["error"]), (2, "invalid_input"))
                    self.assertNotIn("patch_status", row)
