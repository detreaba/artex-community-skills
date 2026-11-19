import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path
from zipfile import ZipFile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from package_skills import build


class PackageTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        (self.root / "LICENSE").write_text("example license\n")
        for name in ("first-skill", "second-skill"):
            files = {
                "SKILL.md": f"---\nname: {name}\ndescription: Fixture\n---\n",
                "scripts/check.py": "print('example')\n",
                "tests/test_check.py": "# sample test\n",
                "examples/gap.json": "{}", "examples/pass.json": "{}",
                "examples/unknown.json": "{}", "examples/customer.json": "private",
                "examples/CVE-2026-12345.json": "{}", "examples/CVE-customer.json": "private",
                ".env": "private", "scripts/__pycache__/check.pyc": "bytecode",
            }
            for path, content in files.items():
                target = self.root / "skills" / name / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content)
        self.skill = self.root / "skills" / "first-skill"

    def test_reproducible_complete_packages_and_manifest(self):
        build(self.root)
        output = self.root / "dist"
        manifest = (output / "SHA256SUMS").read_bytes()
        checksums = []
        for name in ("first-skill", "second-skill"):
            path = output / f"{name}.zip"
            with ZipFile(path) as archive:
                self.assertEqual(archive.namelist(), sorted([
                    f"{name}/LICENSE", f"{name}/SKILL.md", f"{name}/scripts/check.py",
                    f"{name}/tests/test_check.py", f"{name}/examples/gap.json",
                    f"{name}/examples/pass.json", f"{name}/examples/unknown.json",
                    f"{name}/examples/CVE-2026-12345.json",
                ]))
                self.assertEqual(archive.read(f"{name}/LICENSE"), b"example license\n")
            checksums.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {name}.zip\n")
        self.assertEqual(manifest, "".join(checksums).encode("ascii"))
        os.utime(self.skill / "SKILL.md", (100, 100))
        (self.skill / "scripts/check.py").chmod(0o755)
        build(self.root)
        self.assertEqual(manifest, (output / "SHA256SUMS").read_bytes())

    def test_missing_and_mismatched_inputs_preserve_prior_release(self):
        build(self.root)
        output = self.root / "dist"
        snapshot = {f.name: f.read_bytes() for f in output.iterdir()}
        (self.skill / "examples/pass.json").unlink()
        with self.assertRaises(ValueError):
            build(self.root)
        (self.skill / "examples/pass.json").write_text("{}")
        (self.skill / "SKILL.md").write_text("---\nname: other\n---\n")
        with self.assertRaises(ValueError):
            build(self.root)
        self.assertEqual(snapshot, {f.name: f.read_bytes() for f in output.iterdir()})

    def test_rejects_symlinked_files_and_directories(self):
        target = self.skill / "scripts/check.py"
        target.unlink()
        try:
            target.symlink_to(self.root / "LICENSE")
        except OSError as exc:
            self.skipTest(f"symlink creation unavailable: {exc}")
        with self.assertRaises(ValueError):
            build(self.root)
        target.unlink()
        target.write_text("print('example')")
        tests = self.skill / "tests"
        tests.rename(self.root / "unapproved")
        tests.symlink_to(self.root / "unapproved", target_is_directory=True)
        with self.assertRaises(ValueError):
            build(self.root)


if __name__ == "__main__":
    unittest.main()
