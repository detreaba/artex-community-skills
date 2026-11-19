"""Compare one active NGINX Open Source worker with the November 18 advisories."""
from pathlib import Path
import sys

here = Path(__file__).resolve().parent
sys.path.insert(0, str(here if (here / "advisory_evidence.py").is_file() else here.parents[2] / "shared"))
from advisory_evidence import compare, exact, run, unknown, verdict


# First affected upstream release in the nginx.org security list.
START = {
    "CVE-2026-123634": (0, 6, 18),
    "CVE-2026-123007": (1, 9, 5),
    "CVE-2026-121810": (1, 25, 0),
    "CVE-2026-123633": (1, 19, 7),
    "CVE-2026-118899": (1, 13, 0),
    "CVE-2026-113425": (0, 5, 33),
    "CVE-2026-120993": (1, 31, 4),
    "CVE-2026-125283": (0, 9, 6),
    "CVE-2026-120967": (1, 25, 5),
    "CVE-2026-123640": (1, 15, 2),
}
FIXES = {(1, 30): (1, 30, 7), (1, 31): (1, 31, 9)}


def worker_status(first, version):
    if version is None or version[:2] > (1, 31):
        return unknown("An exact upstream worker release on a reviewed line is required.", version)
    if version < first:
        return verdict("outside_affected_range", "The worker predates the vendor's affected range.", version)
    fixed = FIXES.get(version[:2])
    if fixed:
        return compare(version, fixed)
    return verdict("affected_version", "The worker is within the affected range on an older branch. Consult the listed upgrade branches.", version)


def classify(first, record):
    if record.get("source") != "running_worker":
        return unknown("Supply a version identified from the executable of the named running worker.")
    version = exact(record.get("worker_version"))
    result = worker_status(first, version)
    installed = exact(record.get("installed_version"))
    if installed and version and installed != version:
        result["patch_reason"] += " The installed release differs from the running worker. Check other serving workers separately."
    return result


def sources(cve):
    return ["https://nginx.org/en/security_advisories.html", "https://nginx.org/en/CHANGES",
            "https://www.cve.org/CVERecord?id=" + cve]


if __name__ == "__main__":
    sys.exit(run("nginx-oss", START, {"worker_version", "installed_version"}, classify, sources))
