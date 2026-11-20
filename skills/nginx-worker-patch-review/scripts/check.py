"""Review a saved executable observation for one NGINX worker and a named advisory."""
from pathlib import Path
import re
import sys

here = Path(__file__).resolve().parent
sys.path.insert(0, str(here if (here / "advisory_evidence.py").is_file() else here.parents[2] / "shared"))
from advisory_evidence import alias, compare, exact, fields, run, unknown, verdict


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


REWRITE = "CVE-2026-42945"
MAY_FIXES = {(1, 30): (1, 30, 1), (1, 31): (1, 31, 0)}
# All patch numbers from zero through each bound were in nginx.org/download on 2026-11-20.
OSS_LAST_PATCH = {
    (0, 1): 45, (0, 2): 6, (0, 3): 61, (0, 4): 14, (0, 5): 38, (0, 6): 39,
    (0, 7): 69, (0, 8): 55, (0, 9): 7, (1, 0): 15, (1, 1): 19, (1, 2): 9,
    (1, 3): 16, (1, 4): 7, (1, 5): 13, (1, 6): 3, (1, 7): 12, (1, 8): 1,
    (1, 9): 15, (1, 10): 3, (1, 11): 13, (1, 12): 2, (1, 13): 12, (1, 14): 2,
    (1, 15): 12, (1, 16): 1, (1, 17): 10, (1, 18): 0, (1, 19): 10, (1, 20): 2,
    (1, 21): 6, (1, 22): 1, (1, 23): 4, (1, 24): 0, (1, 25): 5, (1, 26): 3,
    (1, 27): 5, (1, 28): 3, (1, 29): 8, (1, 30): 7, (1, 31): 9,
}
# Historical F5 families, each with its first fix and last published patch.
PLUS_PATCHES = {"R32": (6, 7), "R36": (4, 8)}
PLUS37 = (
    "PLS.37.0.0.1", "PLS.37.0.1.1", "PLS.37.0.2.1", "PLS.37.0.3.1", "PLS.37.0.4.1",
    "PLS.37.0.5.1", "PLS.37.0.6.2", "PLS.37.0.7.1", "PLS.37.0.8.1",
    "PLS.37.1.0.1", "PLS.37.1.1.2", "PLS.37.2.0.1", "PLS.37.3.0.1",
)
SHA256 = re.compile(r"[a-fA-F0-9]{64}")
MAY_PROFILE = {REWRITE: (("nginx-oss", "nginx-plus"),
                         {"worker", "deployment_verified", "worker_sha256", "release_provenance"})}


def may_oss(version):
    v = exact(version)
    if v is None or v[2] > OSS_LAST_PATCH.get(v[:2], -1):
        return unknown("The worker release is absent from the reviewed NGINX Open Source archive.")
    if v < (0, 6, 27):
        return verdict("outside_affected_range", "The published worker release predates the affected range.", v)
    if v[:2] in MAY_FIXES:
        return compare(v, MAY_FIXES[v[:2]])
    return verdict("affected_version", "The upstream worker falls in the affected range on an older branch.", v)


def may_plus(version):
    if version in PLUS37:
        return {"patch_status": "outside_affected_range", "patch_reason": "F5 lists this published Plus 37 series as unaffected.",
                "observed_version": version, "first_fixed_on_branch": None}
    match = re.fullmatch(r"(R32|R36)(?: P([1-9][0-9]?))?", version) if isinstance(version, str) else None
    if not match:
        return unknown("Identify an exact F5 Plus release covered by the review.")
    family, patch = match[1], int(match[2] or 0)
    fixed, last = PLUS_PATCHES[family]
    if patch > last:
        return unknown("The stated patch is absent from the reviewed F5 Plus release notes.")
    if patch < fixed:
        status, reason = "affected_version", "The observed F5 Plus worker predates its family’s fixed patch."
    else:
        status, reason = "vendor_fix_present", "The observed F5 Plus worker includes the fix for this advisory."
    return {"patch_status": status, "patch_reason": reason, "observed_version": version,
            "first_fixed_on_branch": f"{family} P{fixed}"}


def may_worker(record):
    proof = fields(record.get("release_provenance", {}), {"ref", "verified", "product", "version", "executable_sha256"})
    worker, ref = alias(record.get("worker")), alias(proof.get("ref"))
    version = record.get("worker_version")
    if record.get("source") != "running_worker" or record.get("deployment_verified") is not True or not worker:
        result = unknown("Identify the executable backing a verified serving worker generation.")
    elif (not ref or ref == record.get("ref") or proof.get("verified") is not True
          or proof.get("product") != record["product"] or proof.get("version") != version):
        result = unknown("Independently identify the upstream executable's product, release and provenance reference.")
    else:
        running, upstream = record.get("worker_sha256"), proof.get("executable_sha256")
        if not (isinstance(running, str) and SHA256.fullmatch(running) and isinstance(upstream, str)
                and SHA256.fullmatch(upstream) and running.lower() == upstream.lower()):
            result = unknown("Match the running executable's SHA-256 to the executable from the verified upstream release.")
        else:
            reader = may_plus if record["product"] == "nginx-plus" else may_oss
            result = reader(version)
            installed = record.get("installed_version")
            if (result["patch_status"] != "unknown" and installed != version
                    and reader(installed)["patch_status"] != "unknown"):
                result["patch_reason"] += " The installed release differs from the worker. Report this generation separately."
    return {**result, "worker": worker, "release_ref": ref}


def worker_status(first, version):
    if version is None or version[:2] > (1, 31):
        return unknown("An exact upstream worker release on a reviewed line is required.", version)
    if version < first:
        return verdict("outside_affected_range", "The worker predates the vendor's affected range.", version)
    fixed = FIXES.get(version[:2])
    if fixed:
        return compare(version, fixed)
    return verdict("affected_version", "The worker is within the affected range on an older branch. Consult the listed upgrade branches.", version)


def classify(rule, record):
    if rule == REWRITE:
        return may_worker(record)
    if record.get("source") != "running_worker":
        return unknown("Supply a version identified from the executable of the named running worker.")
    version = exact(record.get("worker_version"))
    result = worker_status(rule, version)
    installed = exact(record.get("installed_version"))
    if installed and version and installed != version:
        result["patch_reason"] += " The installed release differs from the running worker. Check other serving workers separately."
    return result


def sources(cve):
    if cve == REWRITE:
        return ["https://nginx.org/en/security_advisories.html", "https://nginx.org/download/",
                "https://www.cve.org/CVERecord?id=" + cve, "https://my.f5.com/manage/s/article/K000161019",
                "https://docs.nginx.com/nginx/releases/"]
    return ["https://nginx.org/en/security_advisories.html", "https://nginx.org/en/CHANGES",
            "https://www.cve.org/CVERecord?id=" + cve]


if __name__ == "__main__":
    sys.exit(run("nginx-oss", {**START, REWRITE: REWRITE}, {"worker_version", "installed_version"},
                 classify, sources, advisory_profiles=MAY_PROFILE))
