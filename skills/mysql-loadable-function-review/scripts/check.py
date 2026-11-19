"""Compare a saved MySQL 8.4 registration inventory with its approved allowlist."""
import json
import re
import sys
from collections import Counter, defaultdict

TABLE = "performance_schema.user_defined_functions"
ALIAS = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}")
IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
FILENAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.+\-]{0,254}")
VERSION = re.compile(r"8\.4\.(?:0|[1-9][0-9]{0,5})")
KINDS = ("function", "aggregate")
MAX_ROWS = 10000


def matches(pattern, text):
    return isinstance(text, str) and pattern.fullmatch(text) is not None


def library_name(text):
    return matches(FILENAME, text) and text.upper() != "NULL"


def object_fields(obj, allowed):
    if not isinstance(obj, dict) or obj.keys() - allowed:
        raise ValueError("Unexpected input fields.")


def allowlist(rows):
    if not isinstance(rows, list) or len(rows) > MAX_ROWS:
        raise ValueError("Invalid allowlist.")
    allowed = defaultdict(list)
    for rule in rows:
        object_fields(rule, {"name", "type", "library", "provider"})
        if (not matches(IDENTIFIER, rule.get("name")) or rule["name"].upper() == "NULL" or rule.get("type") not in KINDS
                or "library" not in rule or (rule["library"] is not None and not library_name(rule["library"]))):
            raise ValueError("An approved entry needs its name, type and library or explicit null.")
        if "provider" in rule and (rule["library"] is not None or not matches(ALIAS, rule["provider"])):
            raise ValueError("A named component or plugin requires a provider alias and a null library.")
        allowed[rule["name"].lower()].append(rule)
    return allowed


def observation(row, rules):
    if not rules:
        return "gaps", "unapproved_name"
    kind = row.get("UDF_TYPE")
    if kind not in KINDS:
        return "unresolved", "type_unavailable"
    alternatives = [rule for rule in rules if rule["type"] == kind]
    if not alternatives:
        return "gaps", "unapproved_type"
    if "UDF_LIBRARY" not in row:
        return "unresolved", "library_unavailable"
    library = row["UDF_LIBRARY"]
    if library is None:
        automatic = [rule for rule in alternatives if rule["library"] is None]
        if not automatic:
            return "gaps", "unapproved_registration_class"
        if any("provider" not in rule for rule in automatic):
            return "matched", None
        return "unresolved", "provider_identity_unavailable"
    if not library_name(library):
        return "unresolved", "library_unavailable"
    if any(rule["library"] == library for rule in alternatives):
        return "matched", None
    return "gaps", "unapproved_library"


def review(request):
    object_fields(request, {"policy", "evidence"})
    policy, evidence = request.get("policy", {}), request.get("evidence", {})
    object_fields(policy, {"instance", "build", "ref", "reviewed", "allow"})
    object_fields(evidence, {"instance", "build", "ref", "snapshot", "server_verified", "product",
                             "origin", "version", "source", "coverage", "total", "rows"})
    for record in (policy, evidence):
        for field in ("instance", "build", "ref", "snapshot"):
            if field in record and not matches(ALIAS, record[field]):
                raise ValueError("Invalid evidence alias.")
    out = {"status": "unknown", "instance": policy.get("instance"), "build": policy.get("build"),
           "policy_ref": policy.get("ref"), "evidence_ref": evidence.get("ref"),
           "export_coverage": "unknown", "matched_rows": 0, "gaps": [], "unresolved": []}
    if (policy.get("reviewed") is not True or "allow" not in policy or not policy.get("ref")
            or not all(policy.get(key) and policy[key] == evidence.get(key) for key in ("instance", "build"))):
        out["reason"] = "A reviewed allowlist for the same named instance and build is required."
        return out
    allowed = allowlist(policy["allow"])
    if (evidence.get("server_verified") is not True or not evidence.get("ref") or not evidence.get("snapshot")
            or evidence.get("product") != "mysql" or evidence.get("origin") != "upstream"
            or not matches(VERSION, evidence.get("version")) or evidence.get("source") != TABLE):
        out["reason"] = "Supply an identified Performance Schema export from the running upstream MySQL 8.4 instance."
        return out
    if "rows" not in evidence:
        out["reason"] = "The saved export does not contain a row collection."
        return out
    rows = evidence["rows"]
    if not isinstance(rows, list) or len(rows) > MAX_ROWS:
        raise ValueError("Invalid row collection.")
    total = evidence.get("total", {})
    object_fields(total, {"snapshot", "ref", "unfiltered_rows"})
    count = total.get("unfiltered_rows")
    count_tied = (total.get("snapshot") == evidence["snapshot"] and matches(ALIAS, total.get("ref"))
                  and type(count) is int and count >= 0)
    names = [row.get("UDF_NAME") if isinstance(row, dict) else None for row in rows]
    counts = Counter(name.lower() for name in names if matches(IDENTIFIER, name) and name.upper() != "NULL")
    if count_tied and count < len(counts):
        out["reason"] = "The same-snapshot total is smaller than the number of distinct observed registrations."
        return out
    complete = evidence.get("coverage") == "complete" and count_tied and count == len(rows) == len(counts)
    out["export_coverage"] = "complete" if complete else "partial"
    for position, (row, name) in enumerate(zip(rows, names), 1):
        if not matches(IDENTIFIER, name) or name.upper() == "NULL":
            bucket, reason = "unresolved", "name_unavailable"
        elif counts[name.lower()] != 1:
            bucket, reason = "unresolved", "duplicate_name"
        else:
            bucket, reason = observation(row, allowed.get(name.lower()))
        if bucket == "matched":
            out["matched_rows"] += 1
        else:
            out[bucket].append({"row": position, "reason": reason})
    if out["gaps"]:
        out["status"] = "gap"
        out["reason"] = "At least one identified registration is outside the approved allowlist."
    elif out["unresolved"]:
        out["reason"] = "Some registrations need additional identity or provider evidence."
    elif complete:
        out["status"] = "pass"
        out["reason"] = "Every registration in the complete snapshot satisfies the allowlist."
    else:
        out["reason"] = "A complete export and a matching unfiltered count from this snapshot are required for a pass."
    return out


def reject(*args):
    raise ValueError("Invalid JSON value.")


def unique_keys(pairs):
    obj = dict(pairs)
    if len(obj) != len(pairs):
        reject()
    return obj


def main():
    try:
        limit = 4 * 1024 * 1024
        raw = sys.stdin.buffer.read(limit + 1)
        if len(sys.argv) != 1 or len(raw) > limit:
            raise ValueError("Expected one bounded JSON object on stdin.")
        request = json.loads(raw, object_pairs_hook=unique_keys, parse_constant=reject)
        print(json.dumps(review(request)))
    except (ValueError, RecursionError, OSError):
        print(json.dumps({"error": "invalid_input", "detail": "Check the policy and saved MySQL inventory format."}))
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
