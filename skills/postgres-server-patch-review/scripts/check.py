"""Compare one PostgreSQL backend's two release observations with a named bulletin."""
from pathlib import Path
import sys

here = Path(__file__).resolve().parent
sys.path.insert(0, str(here if (here / "advisory_evidence.py").is_file() else here.parents[2] / "shared"))
from advisory_evidence import compare, exact, run, unknown, verdict


# November 12 fixes share minor versions on each reviewed major, but the
# publisher explicitly excludes different older majors for individual advisories.
FIRST_MAJOR = {
    "CVE-2026-116303": 14,
    "CVE-2026-116304": 14,
    "CVE-2026-116306": 14,
    "CVE-2026-116310": 17,
    "CVE-2026-116311": 14,
    "CVE-2026-116312": 15,
    "CVE-2026-116315": 14,
    "CVE-2026-116316": 14,
    "CVE-2026-116317": 14,
    "CVE-2026-116321": 14,
    "CVE-2026-116322": 18,
    "CVE-2026-116327": 14,
    "CVE-2026-116328": 16,
    "CVE-2026-116329": 18,
    "CVE-2026-116331": 14,
    "CVE-2026-116332": 14,
    "CVE-2026-116333": 17,
    "CVE-2026-116335": 14,
    "CVE-2026-116336": 14,
    "CVE-2026-120139": 14,
    "CVE-2026-120141": 14,
    "CVE-2026-120142": 17,
    "CVE-2026-120143": 14,
    "CVE-2026-120144": 18,
    "CVE-2026-120145": 14,
    "CVE-2026-120146": 14,
    "CVE-2026-120148": 14,
    "CVE-2026-120149": 14,
    "CVE-2026-120150": 14,
    "CVE-2026-120152": 16,
    "CVE-2026-120153": 14,
    "CVE-2026-120154": 14,
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
