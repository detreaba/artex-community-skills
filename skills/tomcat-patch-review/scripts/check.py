"""Review the Catalina implementation loaded by one Tomcat instance using saved evidence."""
import json
from pathlib import Path
import re
import sys
from typing import NamedTuple, Optional


CONNECTOR = "CVE-2026-103119"
DEFAULT_SERVLET = "CVE-2025-24813"
TRIBES = "CVE-2026-34486"
REALM = "CVE-2026-101296"
HTTP2_ASYNC = "CVE-2026-101356"
INTERCEPTOR = "org.apache.catalina.tribes.group.interceptors.EncryptInterceptor"
CATALINA_BUNDLES = ("org.apache.tomcat-catalina", "org.apache.tomcat-embed-core")
COORDINATES = {
    "org.apache.tomcat-coyote": "org.apache.tomcat:tomcat-coyote",
    "org.apache.tomcat-tribes": "org.apache.tomcat:tomcat-tribes",
    "org.apache.tomcat-catalina": "org.apache.tomcat:tomcat-catalina",
    "org.apache.tomcat-embed-core": "org.apache.tomcat.embed:tomcat-embed-core",
}
OCTOBER_FIXES = {"9.0": 123, "10.1": 61, "11.0": 27}
OCTOBER_BULLETINS = (
    "https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.123",
    "https://tomcat.apache.org/security-10.html#Fixed_in_Apache_Tomcat_10.1.61",
    "https://tomcat.apache.org/security-11.html#Fixed_in_Apache_Tomcat_11.0.27",
)
ARCHIVE = "https://archive.apache.org/dist/tomcat/"


class Profile(NamedTuple):
    class_name: str
    bundles: tuple
    first_fix: dict
    sources: tuple
    reviewed: str
    first_affected: Optional[dict] = None
    catalog_class: str = ""


PROFILES = {
    REALM: Profile(
        "org.apache.catalina.realm.JNDIRealm", CATALINA_BUNDLES, {"7.0": None, "8.5": None, **OCTOBER_FIXES},
        ("https://www.cve.org/CVERecord?id=CVE-2026-101296", *OCTOBER_BULLETINS, ARCHIVE),
        "2026-11-20", catalog_class="realm"),
    HTTP2_ASYNC: Profile(
        "org.apache.coyote.AsyncStateMachine", ("org.apache.tomcat-coyote", "org.apache.tomcat-embed-core"), OCTOBER_FIXES,
        ("https://www.cve.org/CVERecord?id=CVE-2026-101356", *OCTOBER_BULLETINS, ARCHIVE),
        "2026-11-20", {"9.0": 118, "10.1": 55, "11.0": 22}, catalog_class="async"),
    TRIBES: Profile(
        INTERCEPTOR, ("org.apache.tomcat-tribes",), {"9.0": 117, "10.1": 54, "11.0": 21},
        ("https://www.cve.org/CVERecord?id=CVE-2026-34486",
         "https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.117",
         "https://tomcat.apache.org/security-10.html#Fixed_in_Apache_Tomcat_10.1.54",
         "https://tomcat.apache.org/security-11.html#Fixed_in_Apache_Tomcat_11.0.21", ARCHIVE),
        "2026-11-20", {"9.0": 116, "10.1": 53, "11.0": 20}),
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


def release_parts(profile, version):
    if profile.catalog_class:
        # An exact catalog match below establishes publication, including the historical milestone spelling.
        match = re.fullmatch(r"([0-9]{1,2}\.[0-9]{1,2})\.([0-9]{1,3})(?:[.-]M[0-9]{1,3})?", version)
        return (match[1], int(match[2])) if match else None
    return RELEASES.get(version)


def october_artifact_matches(record, profile, version, candidates, provenance):
    symbol = record.get("bundle_symbolic_name")
    if provenance is None:
        if symbol not in candidates:
            return False
        candidates = (symbol,)
    elif provenance["ref"] == record["ref"]:
        return False
    if "apache_archive_provenance" in record:
        member = provenance.get("member")
        if not isinstance(member, str) or not member.startswith(f"apache-tomcat-{version}/lib/"):
            return False
        identifiers = {member}
    else:
        identifiers = {f"{COORDINATES[bundle]}:{version}" for bundle in candidates}
    try:
        with Path(__file__).with_name("october-artifacts.tsv").open(encoding="ascii") as catalog:
            for row in catalog:
                identifier, header, digest, classes = row.rstrip("\n").split("\t")
                if identifier in identifiers and symbol == (None if header == "-" else header):
                    return (profile.catalog_class in classes.split(",")
                            and (provenance is None or digest == provenance["loaded_sha256"].lower()))
    except (OSError, UnicodeError, ValueError):
        return False
    return False


def artifact_matches(record, profile, version, line, patch, provenance):
    symbol = record.get("bundle_symbolic_name")
    candidates = profile.bundles
    if provenance is not None:
        loaded, published = provenance.get("loaded_sha256"), provenance.get("published_sha256")
        if not (alias(provenance.get("ref")) and isinstance(loaded, str) and SHA256.fullmatch(loaded)
                and isinstance(published, str) and loaded.lower() == published.lower()):
            return False
        if "apache_archive_provenance" not in record:
            candidates = tuple(bundle for bundle in candidates
                               if provenance.get("coordinate") == f"{COORDINATES[bundle]}:{version}")
    if profile.catalog_class:
        return october_artifact_matches(record, profile, version, candidates, provenance)
    # These releases either omit the header or share a generic value across different JARs.
    if line == "8.5" or (line == "9.0" and patch <= 22) or version in ("9.0.91", "10.1.26"):
        legacy_symbol = f"TOMCAT_9_0_{patch}" if line == "9.0" and 10 <= patch <= 22 else None
        if not candidates or provenance is None or symbol != legacy_symbol:
            return False
        entry = f"{provenance['loaded_sha256'].lower()}  {provenance['coordinate']}"
        try:
            with Path(__file__).with_name("legacy-artifacts.sha256").open(encoding="ascii") as pins:
                return any(line.rstrip() == entry for line in pins)
        except (OSError, UnicodeError):
            return False
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
    parts = release_parts(profile, version)
    if parts is None or parts[0] not in profile.first_fix:
        if profile.catalog_class:
            return "This version is outside the release lines reviewed for this advisory."
        return "This version is outside the published stable releases covered for this advisory."
    line, patch = parts
    if profile.class_name == INTERCEPTOR and line == "9.0" and patch < 13:
        return "This Tomcat Tribes release did not ship the named interceptor class."
    if not artifact_matches(record, profile, version, line, patch, provenance):
        if profile.catalog_class:
            return "The class, release and manifest must identify a published defining JAR. A missing or shared header requires a separate digest record for the exact published Maven coordinate or cataloged Apache archive member."
        return "Identify the defining upstream artifact. A missing or shared bundle name needs the exact published legacy JAR digest and Maven coordinate."
    return None


def release_decision(profile, line, patch):
    fix = profile.first_fix[line]
    if fix is None:
        return "affected_version", "Apache lists this release as affected and has no upstream fix on this line.", None
    first = f"{line}.{fix}"
    if profile.first_affected and patch < profile.first_affected[line]:
        return "outside_affected_range", "This published release predates the affected release on its branch.", None
    if patch < fix:
        if profile.catalog_class:
            return "affected_version", "The loaded artifact is a published release inside Apache's affected range.", first
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
    if profile.catalog_class:
        allowed.add("apache_archive_provenance")
    record = fields(request.get("inventory", {}), allowed)
    provenance = None
    provenance_key = "maven_provenance"
    if "apache_archive_provenance" in record:
        if "maven_provenance" in record:
            raise ValueError("Supply one defining artifact record.")
        provenance_key = "apache_archive_provenance"
    if provenance_key in record:
        identity = "member" if provenance_key == "apache_archive_provenance" else "coordinate"
        provenance = fields(record[provenance_key], {"ref", identity, "loaded_sha256", "published_sha256"})
    scope = {key: alias(record.get(key)) for key in ("asset", "build", "instance")}
    refs = {"inventory": alias(record.get("ref"))}
    if provenance is not None:
        refs[provenance_key] = alias(provenance.get("ref"))
    reason = evidence_problem(record, scope, refs["inventory"], profile, provenance)
    status, first, observed = "unknown", None, None
    if reason is None:
        observed = record["implementation_version"]
        status, reason, first = release_decision(profile, *release_parts(profile, observed))
    if profile.catalog_class:
        reason += " Release attribution relies on the operator's inventory of the class and bytes loaded in this JVM start."
        if advisory == REALM:
            reason += " Review the active JNDI realm and its SASL mechanism separately."
        else:
            reason += " Review HTTP/2 and asynchronous servlet processing on the serving connector separately."
    if advisory == TRIBES:
        reason += (" This status applies only to CVE-2026-34486. Review the EncryptInterceptor advisories "
                   "CVE-2026-29146, CVE-2026-55955, CVE-2026-59084 and CVE-2026-95517 separately "
                   "against Apache's affected ranges for the deployed release.")
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
