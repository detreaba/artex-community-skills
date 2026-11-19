"""Review the Catalina implementation loaded by one Tomcat instance using saved evidence."""
import json
import re
import sys


ADVISORY = "CVE-2026-103119"
BULLETIN = "https://tomcat.apache.org/security-11.html#Fixed_in_Apache_Tomcat_11.0.27"
ARCHIVE = "https://archive.apache.org/dist/tomcat/tomcat-11/"
REVIEWED = "2026-11-19"
CLASS_NAME = "org.apache.catalina.connector.OutputBuffer"
BUNDLES = ("org.apache.tomcat-catalina", "org.apache.tomcat-embed-core")
# Published stable artifacts in the Apache 11.0 archive at review time.
AFFECTED = {f"11.0.{patch}" for patch in range(27) if patch not in (16, 17, 19)}
FIRST_FIXED = "11.0.27"
FIXED = (FIRST_FIXED, "11.0.29")
ALIAS = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,127}")
LIMIT = 16_384


def alias(value):
    return value if isinstance(value, str) and ALIAS.fullmatch(value) else None


def fields(record, allowed):
    if not isinstance(record, dict) or record.keys() - allowed:
        raise ValueError("Unexpected input fields.")
    return record


def classify(record, scope, ref):
    if not all(scope.values()) or not ref or record.get("deployment_verified") is not True:
        return "unknown", "A referenced inventory tied to this build and running JVM is required."
    if record.get("source") != "serving_class_manifest" or record.get("class_name") != CLASS_NAME:
        return "unknown", "Identify the loaded Catalina OutputBuffer class and the manifest of its defining artifact."
    if record.get("bundle_symbolic_name") not in BUNDLES:
        return "unknown", "The loaded artifact must identify the Apache Catalina or embedded-core bundle."
    if record.get("origin") != "upstream":
        return "unknown", "The origin is unverified or requires its distributor's patch decision."
    version = record.get("implementation_version")
    if not isinstance(version, str) or not version or not record.get("upstream_version"):
        return "unknown", "Supply the loaded manifest version and the upstream release identified by provenance."
    if record["upstream_version"] != version:
        return "unknown", "The manifest and release provenance disagree. Reconcile the artifacts for this JVM."
    if version in AFFECTED:
        return "affected_version", "The loaded artifact is a published stable release inside Apache's affected range."
    if version in FIXED:
        return "vendor_fix_present", "The loaded upstream artifact includes this advisory's fix."
    return "unknown", "This version is outside the published stable Tomcat 11.0 releases in this review."


def review(request):
    fields(request, {"advisory", "inventory"})
    if request.get("advisory") != ADVISORY:
        raise ValueError("Unsupported advisory.")
    record = fields(request.get("inventory", {}), {
        "asset", "build", "instance", "ref", "deployment_verified", "source", "class_name",
        "bundle_symbolic_name", "implementation_version", "origin", "upstream_version",
    })
    scope = {key: alias(record.get(key)) for key in ("asset", "build", "instance")}
    ref = alias(record.get("ref"))
    status, reason = classify(record, scope, ref)
    return {
        "advisory": ADVISORY, "product": "Apache Tomcat", "scope": scope, "evidence_refs": {"inventory": ref},
        "observed_version": record.get("implementation_version") if status != "unknown" else None,
        "patch_status": status, "patch_reason": reason,
        "first_fixed_on_branch": FIRST_FIXED if status != "unknown" else None,
        "applicability": "unknown", "reviewed": REVIEWED, "sources": [BULLETIN, ARCHIVE],
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
