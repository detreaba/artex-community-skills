"""Compare an owner-supplied serving-runtime inventory to one named vendor advisory."""
import json
import re
import sys


PHP_NOV_19_FIXES = ((8, 2, 36), (8, 3, 37), (8, 4, 28), (8, 5, 13))

ADVISORIES = {
    "CVE-2026-109618": {
        "runtime": "php",
        "fixed": ((8, 2, 35), (8, 3, 36), (8, 4, 27), (8, 5, 12)),
        "branch_parts": 2,
        "conditions": ("php_serves_web_requests",),
        "source": "https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w",
        "limitation": "PHP identifies all web-serving PHP runtimes for patch review. Memory limits alone cannot establish that the affected behavior is absent.",
    },
    "CVE-2026-115560": {
        "runtime": "php",
        "fixed": PHP_NOV_19_FIXES,
        "branch_parts": 2,
        "conditions": ("upload_progress_enabled", "shared_session_serializer_mismatch"),
        "source": "https://github.com/php/php-src/security/advisories/GHSA-658j-r8rw-q6mx",
        "limitation": "PHP configurations sharing session storage require review even after the upstream update.",
    },
    "CVE-2026-129292": {
        "runtime": "php",
        "fixed": PHP_NOV_19_FIXES,
        "branch_parts": 2,
        "conditions": ("fpm_status_enabled", "request_metadata_reaches_pool", "full_status_rendered_as_html"),
        "source": "https://github.com/php/php-src/security/advisories/GHSA-3mg3-cr28-46gc",
        "limitation": "Review how the affected pool records request metadata and how operators or tools render its status. A private status page alone does not settle this check.",
    },
    "CVE-2026-129538": {
        "runtime": "php",
        "fixed": PHP_NOV_19_FIXES,
        "branch_parts": 2,
        "conditions": ("php_cgi_serves_requests", "cgi_fix_pathinfo_enabled", "affected_frontend_path_mapping"),
        "source": "https://github.com/php/php-src/security/advisories/GHSA-5j3f-64r7-f564",
        "limitation": "The documented condition applies to the php-cgi binary and particular web server mappings. PHP-FPM and the Apache PHP module are outside its scope.",
    },
    "CVE-2026-123865": {
        "runtime": "node",
        "fixed": ((22, 23, 5), (24, 22, 3), (26, 13, 1)),
        "branch_parts": 1,
        "conditions": ("node_handles_http2",),
        "source": "https://nodejs.org/en/blog/vulnerability/november-2026-security-releases",
        "limitation": "Determine whether the serving Node process itself handles HTTP/2. An edge proxy can terminate HTTP/2 separately.",
    },
}
_ALIAS = re.compile(r"[A-Za-z0-9][A-Za-z0-9_./:@-]{0,127}\Z")
_VERSION = re.compile(r"(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\Z")
_LIMIT = 16_384


def _fields(value, allowed):
    if not isinstance(value, dict) or value.keys() - set(allowed):
        raise ValueError("Unexpected input shape.")
    return value


def _alias(value):
    return value if isinstance(value, str) and _ALIAS.fullmatch(value) else None


def _patch_status(profile, inventory):
    if inventory.get("origin") != "upstream":
        return "unknown", "A distribution, custom build or unspecified origin requires a matching vendor package decision.", None
    raw = inventory.get("version")
    if not isinstance(raw, str):
        return "unknown", "The upstream release version is missing or ambiguous.", None
    if profile["runtime"] == "node":
        raw = raw.removeprefix("v")
    match = _VERSION.fullmatch(raw)
    if match is None:
        return "unknown", "Supply an exact stable upstream version for the identified serving runtime.", None
    version = tuple(map(int, match.groups()))
    parts = profile["branch_parts"]
    for fixed in profile["fixed"]:
        if version[:parts] == fixed[:parts]:
            boundary = ".".join(map(str, fixed))
            if version >= fixed:
                return "vendor_fix_present", "The upstream release is at or above the documented fix on this branch.", boundary
            return "affected_version", "The upstream release is in the documented affected range on this branch.", boundary
    return "unknown", "The requested branch is outside the ranges reviewed for this advisory.", None


def _conditions(profile, config, scope):
    ref = _alias(config.get("ref"))
    if not ref or any(config.get(k) != v for k, v in scope.items()):
        return "unknown", None
    fields = profile["conditions"]
    flags = _fields(config.get("conditions", {}), fields)
    if any(v is not None and type(v) is not bool for v in flags.values()):
        raise ValueError("Configuration values must be boolean or null.")
    if any(flags.get(k) is False for k in fields):
        return "conditions_absent", ref
    if all(flags.get(k) is True for k in fields):
        return "conditions_present", ref
    return "unknown", ref


def review(request):
    _fields(request, ("advisory", "inventory", "applicability"))
    advisory = request.get("advisory")
    if not isinstance(advisory, str) or advisory not in ADVISORIES:
        raise ValueError("Select a supported advisory.")
    profile = ADVISORIES[advisory]
    inventory = _fields(request.get("inventory", {}), (
        "asset", "build", "ref", "runtime", "version", "origin", "serving_process_verified"))
    config = _fields(request.get("applicability", {}), ("asset", "build", "ref", "conditions"))
    scope = {key: _alias(inventory.get(key)) for key in ("asset", "build")}
    ref = _alias(inventory.get("ref"))
    patch, detail, fixed = "unknown", "A scoped inventory reference from the deployed serving process is required.", None
    applicability, config_ref = "unknown", None
    if all(scope.values()) and ref and inventory.get("serving_process_verified") is True:
        if inventory.get("runtime") == profile["runtime"]:
            patch, detail, fixed = _patch_status(profile, inventory)
            applicability, config_ref = _conditions(profile, config, scope)
        else:
            detail = "The inventory does not establish the runtime named by the advisory."
    return {
        "advisory": advisory, "scope": scope, "patch_status": patch, "patch_reason": detail,
        "first_fixed_on_branch": fixed, "applicability": applicability,
        "evidence_refs": {"inventory": ref, "configuration": config_ref},
        "sources": [profile["source"]],
        "limitations": [
            "Patch status relies on the operator's evidence of the running package and release origin.",
            "Applicability describes the documented feature conditions only. Application impact requires separate evidence.",
            profile["limitation"],
        ],
    }


def _unique(pairs):
    obj = dict(pairs)
    if len(obj) != len(pairs):
        raise ValueError("Duplicate input key.")
    return obj


def main():
    try:
        raw = sys.stdin.buffer.read(_LIMIT + 1)
        if len(raw) > _LIMIT:
            raise ValueError("Input exceeds 16 KiB.")
        print(json.dumps(review(json.loads(raw, object_pairs_hook=_unique))))
    except (ValueError, RecursionError):
        print(json.dumps({"error": "invalid_input", "detail": "Check the runtime inventory input. No verdict was produced."}))
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
