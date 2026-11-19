"""Check the release provenance of one Apache HTTP Server module."""
from pathlib import Path
import sys

here = Path(__file__).resolve().parent
sys.path.insert(0, str(here if (here / "advisory_evidence.py").is_file() else here.parents[2] / "shared"))
from advisory_evidence import compare, exact, run, unknown, verdict


MODULES = {
    "CVE-2026-119618": ("mod_http2", (2, 4, 55)),
    "CVE-2026-106023": ("mod_md", (2, 4, 30)),
    "CVE-2026-109163": ("mod_vhost_alias", (2, 4, 69)),
}
FIX = (2, 4, 71)


def classify(rule, record):
    module, first = rule
    if record.get("source") != "serving_module_inventory" or record.get("module") != module:
        return unknown("Identify the advisory's module and its provenance in the serving instance.")
    version = exact(record.get("module_release"))
    if version is None:
        return unknown("The record needs an exact release for the observed module artifact.")
    if record.get("module_origin") == "standalone-mod_h2" and module == "mod_http2":
        if (2, 0, 8) <= version <= (2, 0, 42):
            return verdict("affected_version", "The separate upstream mod_h2 release appears in Apache's affected list.", version)
        return unknown("This rule has no documented standalone mod_h2 fix for this version.", version)
    if record.get("module_origin") != "httpd-bundle" or exact(record.get("server_version")) != version:
        return unknown("The module's originating httpd release must match the observed server release.")
    if version[:2] != (2, 4) or version < (2, 4, 1):
        return unknown("This bulletin covers the upstream httpd 2.4 release line.", version)
    if version < first:
        return verdict("outside_affected_range", "This bundled module predates the advisory's affected range.", version)
    return compare(version, FIX)


def sources(cve):
    return ["https://httpd.apache.org/security/vulnerabilities_24.html#" + cve]


if __name__ == "__main__":
    sys.exit(run("apache-httpd", MODULES, {"server_version", "module", "module_origin", "module_release"}, classify, sources))
