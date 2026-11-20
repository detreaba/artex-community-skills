"""Build one ARTEX importable archive per skill and write SHA256SUMS."""

import hashlib
import os
import re
from pathlib import Path
from tempfile import TemporaryDirectory
from zipfile import ZIP_STORED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
FIXED_FILES = ("SKILL.md", "scripts/check.py", "examples/gap.json",
               "examples/pass.json", "examples/unknown.json")
USES_EVIDENCE_READER = {"nginx-worker-patch-review", "apache-module-patch-review", "postgres-server-patch-review"}


def files_for_skill(skill):
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", skill.name):
        raise ValueError(f"Invalid skill name: {skill.name}")
    for directory in (skill, skill / "scripts", skill / "tests", skill / "examples"):
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError(f"Expected a regular directory: {directory}")
    tests = sorted(f for f in (skill / "tests").glob("test_*.py")
                   if re.fullmatch(r"test_[a-zA-Z0-9_]+\.py", f.name))
    if not tests:
        raise ValueError(f"Missing skill tests: {skill.name}")
    advisory_examples = sorted(f for f in (skill / "examples").glob("CVE-*.json")
                               if re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}\.json", f.name))
    entries = [skill / name for name in FIXED_FILES] + tests + advisory_examples
    for entry in entries:
        if entry.is_symlink() or not entry.is_file():
            raise ValueError(f"Expected a regular package file: {entry}")

    guide = (skill / "SKILL.md").read_text(encoding="utf-8").splitlines()
    if not guide or guide[0] != "---" or "---" not in guide[1:]:
        raise ValueError(f"Missing SKILL.md frontmatter: {skill.name}")
    header = guide[1:guide.index("---", 1)]
    if [line.strip() for line in header if line.startswith("name:")] != [f"name: {skill.name}"]:
        raise ValueError(f"Frontmatter name must match the skill directory: {skill.name}")
    files = {f.relative_to(skill).as_posix(): f for f in entries}
    if skill.name in USES_EVIDENCE_READER:
        reader = skill.parents[1] / "shared" / "advisory_evidence.py"
        if reader.parent.is_symlink() or reader.is_symlink() or not reader.is_file():
            raise ValueError("Missing regular shared evidence reader.")
        files["scripts/advisory_evidence.py"] = reader
    return files


def build(root=ROOT):
    skills = root / "skills"
    license_file = root / "LICENSE"
    output = root / "dist"
    if skills.is_symlink() or not skills.is_dir():
        raise ValueError("Missing regular skills directory")
    if license_file.is_symlink() or not license_file.is_file():
        raise ValueError("Missing regular LICENSE file")
    if output.is_symlink():
        raise ValueError("dist must be a regular directory")
    packages = {}
    for skill in sorted(skills.iterdir()):
        if skill.is_dir() and not skill.name.startswith("."):
            packages[skill.name] = {**files_for_skill(skill), "LICENSE": license_file}
    if not packages:
        raise ValueError("No skills found")

    output.mkdir(exist_ok=True)
    if any(f.stem not in packages for f in output.glob("*.zip")):
        raise ValueError("An unrelated ZIP is already in dist. Move it before building.")
    with TemporaryDirectory(dir=output) as staging_dir:
        staging = Path(staging_dir)
        checksums = []
        for name, entries in packages.items():
            archive = staging / f"{name}.zip"
            with ZipFile(archive, "w", compression=ZIP_STORED) as bundle:
                for relative, path in sorted(entries.items()):
                    # ZipInfo's default timestamp is fixed. Store entries verbatim
                    # so checksums also agree across compression library versions.
                    info = ZipInfo(f"{name}/{relative}")
                    info.create_system = 3
                    info.external_attr = 0o100644 << 16
                    bundle.writestr(info, path.read_bytes())
            checksums.append(f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n")
        manifest = staging / "SHA256SUMS"
        manifest.write_bytes("".join(checksums).encode("ascii"))
        for archive in sorted(staging.glob("*.zip")):
            os.replace(archive, output / archive.name)
        os.replace(manifest, output / manifest.name)
    return checksums


if __name__ == "__main__":
    print("".join(build()), end="")
