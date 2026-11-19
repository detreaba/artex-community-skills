"""Read one owner-supplied release observation and report its evidentiary scope."""
import json
import re
import sys


LIMIT = 16_384
ALIAS = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_./:@-]{0,127}")
PART = r"(0|[1-9][0-9]{0,3})"
VERSIONS = {length: re.compile(r"\.".join([PART] * length)) for length in (2, 3)}


def exact(value, length=3):
    match = VERSIONS[length].fullmatch(value) if isinstance(value, str) else None
    return tuple(map(int, match.groups())) if match else None


def display(version):
    return ".".join(map(str, version))


def verdict(status, reason, version=None, fixed=None):
    return {"patch_status": status, "patch_reason": reason,
            "observed_version": display(version) if version else None,
            "first_fixed_on_branch": display(fixed) if fixed else None}


def unknown(reason, version=None):
    return verdict("unknown", reason, version)


def compare(version, fixed):
    if version < fixed:
        return verdict("affected_version", "The observed release falls in the documented affected range.", version, fixed)
    return verdict("vendor_fix_present", "The observed upstream release includes the fix on this branch.", version, fixed)


def fields(record, allowed):
    if not isinstance(record, dict) or record.keys() - allowed:
        raise ValueError("Unexpected input fields.")
    return record


def alias(value):
    return value if isinstance(value, str) and ALIAS.fullmatch(value) else None


def unique_keys(pairs):
    record = dict(pairs)
    if len(record) != len(pairs):
        raise ValueError("Duplicate JSON key.")
    return record


def run(product, catalog, extra_fields, classify, sources):
    try:
        raw = sys.stdin.buffer.read(LIMIT + 1)
        if len(raw) > LIMIT:
            raise ValueError("Input exceeds 16 KiB.")
        data = fields(json.loads(raw, object_pairs_hook=unique_keys), {"asset", "build", "advisory", "evidence"})
        cve = data.get("advisory")
        if not isinstance(cve, str) or cve not in catalog:
            raise ValueError("Choose an advisory listed in this skill.")
        scope = {key: alias(data.get(key)) for key in ("asset", "build")}
        base_fields = {"asset", "build", "ref", "product", "origin", "source"}
        record = fields(data.get("evidence", {}), base_fields | extra_fields)
        ref = alias(record.get("ref"))
        if not ref or not all(scope.values()) or any(record.get(k) != v for k, v in scope.items()):
            ref = None
            outcome = unknown("A referenced observation for this asset and build is required.")
        elif record.get("product") != product or record.get("origin") != "upstream":
            outcome = unknown("Verify the upstream product identity. Distribution and custom builds need their vendor's patch evidence.")
        else:
            outcome = classify(catalog[cve], record)
        print(json.dumps({"advisory": cve, "product": product, **scope, "evidence_ref": ref,
                          **outcome, "applicability": "unknown", "sources": sources(cve)}))
    except (ValueError, RecursionError):
        print(json.dumps({"error": "invalid_input", "detail": "Check the advisory, evidence fields and input size."}))
        return 2
    return 0
