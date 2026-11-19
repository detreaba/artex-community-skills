"""Review a saved worker's normalized, ordered ImageMagick delegate policy."""
import json
import re
import sys


MAX_BYTES = 1024 * 1024
MAX_RULES = 1024
ALIAS = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}")
TAG = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}")
RELEASE = re.compile(r"7\.1\.([12])-(0|[1-9][0-9]?)")
COVERAGE = ("loaded", "order", "files_and_includes", "builtins", "stealth", "runtime")
OTHER_DOMAINS = {"cache", "coder", "filter", "module", "path", "resource", "system"}
PLACEHOLDERS = {"unknown", "redacted", "unavailable", "unverified", "missing", "unset", "unspecified", "null", "none"}
DENY, ALLOW, EITHER = 1, 2, 3


def supported(version):
    match = RELEASE.fullmatch(version) if isinstance(version, str) else None
    if not match:
        return False
    series, patch = map(int, match.groups())
    if series == 1:
        return patch <= 47 and patch != 42
    return patch <= 36 and patch != 4 and not 20 <= patch <= 23


def alias(value):
    return isinstance(value, str) and ALIAS.fullmatch(value) is not None and value.lower() not in PLACEHOLDERS


def object_value(value):
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError("expected an object")
    return value


def result(status, reason, named=(), uncertain=(), other="unassessed", missing=()):
    return {"status": status, "reason": reason, "named_execute": list(named),
            "uncertain_names": list(uncertain), "other_execute": other, "missing": list(missing)}


def execute_right(rights):
    if not isinstance(rights, str) or not rights.isascii():
        return EITHER
    tokens = {part.strip().lower() for part in rights.split("|")}
    if tokens == {"none"}:
        return DENY
    if tokens == {"all"}:
        return ALLOW
    if tokens <= {"read", "write", "execute"}:
        return ALLOW if "execute" in tokens else DENY
    return EITHER


def policy_decision(rows):
    rules = []
    names = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) - {"domain", "pattern", "rights"}:
            raise ValueError("expected normalized rules")
        domain = row.get("domain")
        domain = domain.lower() if isinstance(domain, str) and domain.isascii() else None
        if domain in OTHER_DOMAINS:
            continue
        pattern = row.get("pattern")
        if isinstance(pattern, str) and TAG.fullmatch(pattern) and pattern.lower() not in PLACEHOLDERS:
            names.add(pattern)
        elif pattern != "*":
            # A missing, redacted or complex pattern might match any subset.
            pattern = None
        rules.append((domain == "delegate", pattern, execute_right(row.get("rights"))))

    def decision(name):
        # The residual class (name = None) covers every tag outside the literals.
        rights = ALLOW
        for delegate, pattern, mask in rules:
            if pattern is None:
                rights |= mask
            elif pattern == "*" or pattern == name:
                rights = mask if delegate else rights | mask
        return rights

    allowed = []
    uncertain = []
    for name in sorted(names):
        verdict = decision(name)
        if verdict == ALLOW:
            allowed.append(name)
        elif verdict == EITHER:
            uncertain.append(name)
    other = {DENY: "denied", ALLOW: "allowed", EITHER: "unknown"}[decision(None)]
    if allowed or other == "allowed":
        return result("gap", "execute_allowed", allowed, uncertain, other)
    if uncertain or other == "unknown":
        return result("unknown", "unresolved_rules", allowed, uncertain, other)
    return result("pass", "all_denied", other=other)


def review(data):
    if not isinstance(data, dict):
        raise ValueError("expected an object")
    worker = object_value(data.get("worker"))
    export = object_value(data.get("export"))
    if not all(alias(x) for x in (worker.get("id"), worker.get("build"),
                                  export.get("worker"), export.get("build"), export.get("ref"))):
        return result("unknown", "worker_evidence_missing")
    if (worker["id"], worker["build"]) != (export["worker"], export["build"]):
        return result("unknown", "worker_build_mismatch")
    if (export.get("product") != "imagemagick" or not alias(export.get("version_ref"))
            or export.get("origin") not in ("upstream", "upstream_equivalent")):
        return result("unknown", "unverified_build")
    if not supported(export.get("version")):
        return result("unknown", "unsupported_release")
    if export.get("kind") != "effective":
        return result("unknown", "effective_export_required")
    coverage = object_value(export.get("coverage"))
    missing = [field for field in COVERAGE if coverage.get(field) is not True]
    if missing:
        return result("unknown", "incomplete_coverage", missing=missing)
    rows = export.get("rules")
    if rows is None:
        return result("unknown", "rules_unavailable")
    if not isinstance(rows, list) or len(rows) > MAX_RULES:
        raise ValueError("invalid rules list")
    return policy_decision(rows)


def unique_keys(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("duplicate key")
        obj[key] = value
    return obj


def invalid_constant(_):
    raise ValueError("invalid JSON number")


if __name__ == "__main__":
    try:
        raw = sys.stdin.buffer.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError("oversize input")
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_keys,
                          parse_constant=invalid_constant)
        print(json.dumps(review(data)))
    except (ValueError, RecursionError):
        print(json.dumps({"status": "invalid_input"}))
        sys.exit(2)
