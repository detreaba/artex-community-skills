"""Compare one PostgreSQL backend's two release observations with a named bulletin."""
from pathlib import Path
import sys

here = Path(__file__).resolve().parent
sys.path.insert(0, str(here if (here / "advisory_evidence.py").is_file() else here.parents[2] / "shared"))
from advisory_evidence import compare, exact, run, unknown, verdict


# The four bulletins share a release date but name different affected majors.
FIRST_MAJOR = {
    "CVE-2026-116316": 14,
    "CVE-2026-120145": 14,
    "CVE-2026-116310": 17,
    "CVE-2026-116328": 16,
}
FIXED_MINOR = {14: 25, 15: 20, 16: 16, 17: 12, 18: 7}


def classify(first_major, record):
    if record.get("source") != "connected_server":
        return unknown("Use the two reported versions from the same connected PostgreSQL backend.")
    version = exact(record.get("server_version"), 2)
    number = record.get("server_version_num")
    if version is None or type(number) not in (int, str):
        return unknown("An exact stable server_version and its server_version_num are required.")
    major, minor = version
    if str(number) != str(major * 10000 + minor):
        return unknown("The connected server's text and numeric version records disagree.")
    if major not in FIXED_MINOR:
        return unknown("This edition reviews the PostgreSQL 14 through 18 security tables.", version)
    if major < first_major:
        return verdict("outside_affected_range", "The vendor explicitly excludes this older major for the named advisory.", version)
    return compare(version, (major, FIXED_MINOR[major]))


def sources(cve):
    return ["https://www.postgresql.org/support/security/" + cve + "/"]


if __name__ == "__main__":
    sys.exit(run("postgresql", FIRST_MAJOR, {"server_version", "server_version_num"}, classify, sources))
