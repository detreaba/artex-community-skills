"""Review the Catalina implementation loaded by one Tomcat instance using saved evidence."""
import json
import re
import sys
from typing import NamedTuple


CONNECTOR = "CVE-2026-103119"
DEFAULT_SERVLET = "CVE-2025-24813"
CATALINA_BUNDLES = ("org.apache.tomcat-catalina", "org.apache.tomcat-embed-core")
COORDINATES = {
    "org.apache.tomcat-catalina": "org.apache.tomcat:tomcat-catalina",
    "org.apache.tomcat-embed-core": "org.apache.tomcat.embed:tomcat-embed-core",
}
ARCHIVE = "https://archive.apache.org/dist/tomcat/"


class Profile(NamedTuple):
    class_name: str
    bundles: tuple
    first_fix: dict
    sources: tuple
    reviewed: str


PROFILES = {
    CONNECTOR: Profile(
        "org.apache.catalina.connector.OutputBuffer", CATALINA_BUNDLES, {"11.0": 27},
        ("https://tomcat.apache.org/security-11.html#Fixed_in_Apache_Tomcat_11.0.27", ARCHIVE + "tomcat-11/"),
        "2026-11-19"),
    DEFAULT_SERVLET: Profile(
        "org.apache.catalina.servlets.DefaultServlet", CATALINA_BUNDLES,
        {"8.5": None, "9.0": 99, "10.1": 35, "11.0": 3},
        ("https://www.cve.org/CVERecord?id=CVE-2025-24813",
         "https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.99",
         "https://tomcat.apache.org/security-10.html#Fixed_in_Apache_Tomcat_10.1.35",
         "https://tomcat.apache.org/security-11.html#Fixed_in_Apache_Tomcat_11.0.3", ARCHIVE), "2026-11-20"),
}

# Numeric versions present in both Apache's release archive and Maven Central on 2026-11-20.
# The upper bound and unpublished patch numbers belong to each individual release line.
PUBLISHED = {
    "8.5": (100, (1, 7, 10, 17, 18, 22, 25, 26, 36, 44, 48, 52, 62, 67, 74, 80)),
    "9.0": (124, (0, 3, 9, 15, 18, 23, 25, 28, 32, 42, 47, 49, 51, 57, 61, 66, 77, 92, 101, 103, 114)),
    "10.1": (62, (3, 21, 22, 27, 32, 37, 38, 51, 58)),
    "11.0": (29, (16, 17, 19, 28)),
}
# Apache announced four plain-numbered builds as betas.
BETA = {"8.5.0", "8.5.2", "9.0.1", "9.0.2"}
RELEASES = {f"{line}.{patch}": (line, patch) for line, (last, gaps) in PUBLISHED.items()
            for patch in range(last + 1) if patch not in gaps and f"{line}.{patch}" not in BETA}
SHA256 = re.compile(r"[0-9a-fA-F]{64}")
ALIAS = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,127}")
LIMIT = 16_384


def alias(value):
    return value if isinstance(value, str) and ALIAS.fullmatch(value) else None


def fields(record, allowed):
    if not isinstance(record, dict) or record.keys() - allowed:
        raise ValueError("Unexpected input fields.")
    return record


def artifact_matches(record, profile, version, line, patch, provenance):
    symbol = record.get("bundle_symbolic_name")
    candidates = profile.bundles
    if provenance is not None:
        loaded, published = provenance.get("loaded_sha256"), provenance.get("published_sha256")
        if not (alias(provenance.get("ref")) and isinstance(loaded, str) and SHA256.fullmatch(loaded)
                and isinstance(published, str) and loaded.lower() == published.lower()):
            return False
        candidates = tuple(bundle for bundle in candidates
                           if provenance.get("coordinate") == f"{COORDINATES[bundle]}:{version}")
    # These releases either omit the header or share a generic value across different JARs.
    if line == "8.5" or (line == "9.0" and patch <= 22) or version in ("9.0.91", "10.1.26"):
        legacy_symbol = f"TOMCAT_9_0_{patch}" if line == "9.0" and 10 <= patch <= 22 else None
        return bool(candidates) and provenance is not None and symbol == legacy_symbol
    return symbol in candidates


def evidence_problem(record, scope, ref, profile, provenance):
    if not all(scope.values()) or not ref or record.get("deployment_verified") is not True:
        return "A referenced inventory tied to this build and running JVM is required."
    if record.get("source") != "serving_class_manifest" or record.get("class_name") != profile.class_name:
        return f"Identify the loaded {profile.class_name} class and the manifest of its defining artifact."
    if record.get("origin") != "upstream":
        return "The origin is unverified or requires its distributor's patch decision."
    version = record.get("implementation_version")
    if not isinstance(version, str) or record.get("upstream_version") != version:
        return "Reconcile the loaded manifest and the upstream release attributed to these bytes."
    if version not in RELEASES or RELEASES[version][0] not in profile.first_fix:
        return "This version is outside the published stable releases covered for this advisory."
    line, patch = RELEASES[version]
    if not artifact_matches(record, profile, version, line, patch, provenance):
        return "Identify the defining upstream artifact. Older or generic manifests need matching Maven provenance."
    return None


def release_decision(profile, line, patch):
    fix = profile.first_fix[line]
    if fix is None:
        return "affected_version", "Apache lists this release as affected and has no upstream fix on this line.", None
    first = f"{line}.{fix}"
    if patch < fix:
        return "affected_version", "The loaded artifact is a published stable release inside Apache's affected range.", first
    return "vendor_fix_present", "The loaded upstream artifact includes this advisory's fix.", first


def review(request):
    fields(request, {"advisory", "inventory"})
    advisory = request.get("advisory")
    if not isinstance(advisory, str) or advisory not in PROFILES:
        raise ValueError("Unsupported advisory.")
    profile = PROFILES[advisory]
    allowed = {"asset", "build", "instance", "ref", "deployment_verified", "source", "class_name",
               "bundle_symbolic_name", "implementation_version", "origin", "upstream_version"}
    if advisory != CONNECTOR:
        allowed.add("maven_provenance")
    record = fields(request.get("inventory", {}), allowed)
    provenance = None
    if "maven_provenance" in record:
        provenance = fields(record["maven_provenance"], {"ref", "coordinate", "loaded_sha256", "published_sha256"})
    scope = {key: alias(record.get(key)) for key in ("asset", "build", "instance")}
    refs = {"inventory": alias(record.get("ref"))}
    if provenance is not None:
        refs["maven_provenance"] = alias(provenance.get("ref"))
    reason = evidence_problem(record, scope, refs["inventory"], profile, provenance)
    status, first, observed = "unknown", None, None
    if reason is None:
        observed = record["implementation_version"]
        status, reason, first = release_decision(profile, *RELEASES[observed])
    return {
        "advisory": advisory, "product": "Apache Tomcat", "scope": scope, "evidence_refs": refs,
        "observed_version": observed, "patch_status": status, "patch_reason": reason,
        "first_fixed_on_branch": first, "applicability": "unknown",
        "reviewed": profile.reviewed, "sources": list(profile.sources),
    }


def unique_keys(pairs):
    record = dict(pairs)
    if len(record) != len(pairs):
        raise ValueError("Duplicate JSON key.")
    return record


def reject_constant(value):
    raise ValueError(f"Invalid JSON constant: {value}")


def main():
    try:
        raw = sys.stdin.buffer.read(LIMIT + 1)
        if len(raw) > LIMIT:
            raise ValueError("Input exceeds 16 KiB.")
        request = json.loads(raw, object_pairs_hook=unique_keys, parse_constant=reject_constant)
        print(json.dumps(review(request)))
    except (ValueError, RecursionError):
        print(json.dumps({"error": "invalid_input", "detail": "Check the advisory, inventory fields and input size."}))
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
