"""Compare one recorded framework package with a named upstream security bulletin."""
import json
import re
import sys


# Each window is (start, first fixed, end exclusive). Its end limits conclusions
# about later release lines. Older unsupported Django branches need separate evidence.
DJANGO_CACHE_WINDOWS = (
    ((5, 2, 0), (5, 2, 19), (5, 3, 0)),
    ((6, 0, 0), (6, 0, 10), (6, 1, 0)),
    ((6, 1, 0), (6, 1, 3), (6, 2, 0)),
)
DJANGO_BULLETIN = "https://www.djangoproject.com/weblog/2026/nov/03/security-releases/"
NEXT_ADVISORIES = "https://github.com/vercel/next.js/security/advisories/"
ADVISORIES = {
    "CVE-2026-119349": {
        "ecosystem": "npm", "package": "next", "published": "2026-11-03",
        "windows": (((16, 0, 0), (16, 4, 5), (17, 0, 0)),),
        "outside": (((0, 0, 0), (16, 0, 0)),),
        "conditions": ("app_router", "binary_arguments_to_use_cache"),
        "sources": [NEXT_ADVISORIES + "GHSA-rhh4-g77r-r9qj"],
    },
    "CVE-2026-119351": {
        "ecosystem": "npm", "package": "next", "published": "2026-11-03",
        "windows": (((16, 2, 0), (16, 4, 5), (17, 0, 0)),),
        "outside": (((0, 0, 0), (16, 2, 0)),),
        "conditions": ("cache_components", "nested_cache_reads_root_params_with_pending_promises"),
        "sources": [NEXT_ADVISORIES + "GHSA-vc7v-qv4w-wrv8"],
    },
    "CVE-2026-118514": {
        "ecosystem": "composer", "package": "symfony/http-foundation", "published": "2026-11-04",
        "windows": (
            ((0, 0, 0), (5, 4, 56), (6, 0, 0)),
            ((6, 0, 0), (6, 4, 50), (7, 0, 0)),
            ((7, 0, 0), (7, 4, 23), (8, 0, 0)),
            ((8, 0, 0), (8, 1, 11), (9, 0, 0)),
        ),
        "conditions": ("get_rule_without_head",),
        "sources": ["https://symfony.com/blog/cve-2026-118514-head-requests-bypass-the-methods-option-of-access-control-and-firewalls-incomplete-fix-for-cve-2026-45075"],
    },
    "CVE-2026-113593": {
        "ecosystem": "pypi", "package": "django", "published": "2026-11-03",
        "windows": DJANGO_CACHE_WINDOWS,
        "conditions": ("django_page_cache_in_use", "vary_header_present"),
        "sources": [DJANGO_BULLETIN, "https://www.cve.org/CVERecord?id=CVE-2026-113593"],
    },
    "CVE-2026-113733": {
        "ecosystem": "pypi", "package": "django", "published": "2026-11-03",
        "windows": DJANGO_CACHE_WINDOWS[1:],
        "outside": (((5, 2, 0), (5, 3, 0)),),
        "conditions": ("view_only_user_admin", "affected_user_model_layout"),
        "sources": [DJANGO_BULLETIN, "https://www.cve.org/CVERecord?id=CVE-2026-113733"],
    },
}

REVIEWED = "2026-11-19"
ALIAS = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_@./:-]{0,127}")
COMPONENT = r"(0|[1-9][0-9]{0,5})"
VERSION = re.compile(COMPONENT + r"\." + COMPONENT + r"\." + COMPONENT)
MAX_BYTES = 16_384


def check_fields(obj, allowed):
    if not isinstance(obj, dict) or obj.keys() - set(allowed):
        raise ValueError("Unexpected evidence fields.")
    return obj


def alias(value):
    return value if isinstance(value, str) and ALIAS.fullmatch(value) else None


def release(value, ecosystem):
    if not isinstance(value, str) or len(value) > 32:
        return None
    if ecosystem == "composer":
        value = value.removeprefix("v")
    if ecosystem == "pypi" and value.count(".") == 1:
        value += ".0"
    match = VERSION.fullmatch(value)
    return tuple(map(int, match.groups())) if match else None


def classify(profile, version):
    for start, fixed, end in profile["windows"]:
        if start <= version < end:
            cutoff = ".".join(map(str, fixed))
            if version < fixed:
                return "affected_version", cutoff, "The release falls in the vendor's affected range."
            return "vendor_fix_present", cutoff, "The identified upstream release includes the named fix."
    if any(start <= version < end for start, end in profile.get("outside", ())):
        return "outside_affected_range", None, "This upstream release falls outside the documented affected range."
    return "unknown", None, "This release line is outside the branches reviewed by this checker."


def feature_status(profile, config, scope):
    conditions = check_fields(config.get("conditions", {}), profile["conditions"])
    if any(v is not None and type(v) is not bool for v in conditions.values()):
        raise ValueError("A condition must be true, false or null.")
    ref = alias(config.get("ref"))
    if not ref or any(config.get(k) != v for k, v in scope.items()):
        return "unknown", None
    if any(conditions.get(k) is False for k in profile["conditions"]):
        return "conditions_absent", ref
    if all(conditions.get(k) is True for k in profile["conditions"]):
        return "conditions_present", ref
    return "unknown", ref


def review(request):
    check_fields(request, ("advisory", "inventory", "applicability"))
    advisory = request.get("advisory")
    if not isinstance(advisory, str) or advisory not in ADVISORIES:
        raise ValueError("Select a supported advisory.")
    profile = ADVISORIES[advisory]
    inventory = check_fields(request.get("inventory", {}), (
        "asset", "build", "ref", "ecosystem", "package", "version", "origin", "deployment_verified"))
    config = check_fields(request.get("applicability", {}), ("asset", "build", "ref", "conditions"))
    scope = {k: alias(inventory.get(k)) for k in ("asset", "build")}
    inv_ref = alias(inventory.get("ref"))
    package = inventory.get("package")
    if isinstance(package, str) and profile["ecosystem"] == "pypi":
        package = package.lower()
    identity_matches = package == profile["package"] and inventory.get("ecosystem") == profile["ecosystem"]
    status, fixed, detail = "unknown", None, "A referenced inventory for the exact package in the deployed build is required."
    applicability, config_ref = "unknown", None
    parsed = None
    if identity_matches and all(scope.values()) and inv_ref and inventory.get("deployment_verified") is True:
        applicability, config_ref = feature_status(profile, config, scope)
        parsed = release(inventory.get("version"), profile["ecosystem"])
        if inventory.get("origin") != "upstream":
            detail = "The supplied package origin requires separate vendor or backport evidence."
        elif parsed is None:
            detail = "An exact stable release from the deployed package is required."
        else:
            status, fixed, detail = classify(profile, parsed)
    return {
        "advisory": advisory, "package": profile["package"], "ecosystem": profile["ecosystem"],
        "scope": scope, "version": ".".join(map(str, parsed)) if parsed else None,
        "patch_status": status, "patch_reason": detail, "first_fixed_in_range": fixed,
        "applicability": applicability, "evidence_refs": {"inventory": inv_ref, "configuration": config_ref},
        "published": profile["published"], "reviewed": REVIEWED, "sources": profile["sources"],
        "limitations": ["Results concern the named advisory and supplied build only.",
                        "Configuration evidence describes features. Actual disclosure or access requires separate evidence."],
    }


def unique_keys(pairs):
    obj = dict(pairs)
    if len(obj) != len(pairs):
        raise ValueError("Duplicate input key.")
    return obj


def main():
    try:
        raw = sys.stdin.buffer.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError("Input exceeds the supported size.")
        result = review(json.loads(raw, object_pairs_hook=unique_keys))
    except (ValueError, RecursionError):
        print(json.dumps({"error": "invalid_input", "detail": "Check the named advisory, scoped fields and input size."}))
        return 2
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
