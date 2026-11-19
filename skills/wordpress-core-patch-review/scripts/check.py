"""Compare a deployed WordPress core release with a named WordPress core security advisory."""
import json
import re
import sys


def _fixes(text):
    """Map each release branch (major, minor) to its first fixed release."""
    table = {}
    for item in text.split():
        version = tuple(int(x) for x in item.split("."))
        table[version[:2]] = version
    return table


# First fixed release per branch, transcribed from the WordPress security advisories
# (github.com/WordPress/wordpress-develop/security/advisories) and their release posts.
WP_ADVISORY = "https://github.com/WordPress/wordpress-develop/security/advisories/"
ADVISORIES = {
    "CVE-2026-60137": {
        "ghsa": "GHSA-fpp7-x2x2-2mjf", "published": "2026-07-17", "kev_date_added": "2026-07-21",
        # 7.1 beta2 shipped the fix, so the first 7.1 release includes it.
        "fixed": _fixes("6.8.6 6.9.5 7.0.2 7.1.0"),
        "not_affected_below": (6, 8, 0),
        "conditions": (),
        "sources": [WP_ADVISORY + "GHSA-fpp7-x2x2-2mjf", "https://wordpress.org/news/2026/07/wordpress-7-0-2-release/"],
        "note": "On 6.9 and later this SQL injection chains with CVE-2026-63030 to unauthenticated remote code execution.",
    },
    "CVE-2026-63030": {
        "ghsa": "GHSA-ff9f-jf42-662q", "published": "2026-07-17", "kev_date_added": "2026-07-21",
        "fixed": _fixes("6.9.5 7.0.2 7.1.0"),
        "not_affected_below": (6, 9, 0),
        "conditions": (),
        "sources": [WP_ADVISORY + "GHSA-ff9f-jf42-662q", "https://wordpress.org/news/2026/07/wordpress-7-0-2-release/"],
        "note": "Chains with CVE-2026-60137. The release post states that 6.8 and earlier are not affected by this issue.",
    },
    "CVE-2026-87902": {
        "ghsa": "GHSA-7hp8-65ch-5whp", "published": "2026-09-22", "kev_date_added": "2026-09-25",
        "fixed": _fixes("7.1.2 7.0.6 6.9.9 6.8.10 6.7.9 6.6.9 6.5.12 6.4.12 6.3.12 6.2.13 6.1.14 6.0.16 5.9.18 "
                        "5.8.17 5.7.19 5.6.21 5.5.22 5.4.23 5.3.25 5.2.28 5.1.26 5.0.29 4.9.33 4.8.32 4.7.37"),
        # The CNA record lists every release below 7.1.2 as affected; branches before 4.7 received no backport.
        "affected_without_backport_below": (4, 7, 0), "fix_for_unbackported": (7, 1, 2),
        "conditions": ("theme_has_page_prefixed_directory", "includable_php_target_readable"),
        "sources": [WP_ADVISORY + "GHSA-7hp8-65ch-5whp", "https://wordpress.org/news/2026/09/wordpress-7-1-2-release/",
                    "https://www.cve.org/CVERecord?id=CVE-2026-87902"],
        "note": "Remote code execution needs both documented pre-conditions: the active theme and a readable local PHP file.",
    },
    "CVE-2026-119977": {
        "ghsa": "GHSA-4w3m-c66w-69mg", "published": "2026-10-29", "kev_date_added": "2026-11-03",
        "fixed": _fixes("7.1.4 7.0.8 6.9.11 6.8.12 6.7.11 6.6.11 6.5.14 6.4.14 6.3.14 6.2.15 6.1.16 6.0.18 5.9.20 "
                        "5.8.19 5.7.21 5.6.23 5.5.24 5.4.25 5.3.27 5.2.30 5.1.28 5.0.31 4.9.35 4.8.34 4.7.39"),
        "conditions": (),
        "sources": [WP_ADVISORY + "GHSA-4w3m-c66w-69mg", "https://wordpress.org/news/2026/10/wordpress-7-1-4/",
                    "https://www.cve.org/CVERecord?id=CVE-2026-119977"],
        "note": ("The vendor advisory carries no CVE ID. The CNA record for CVE-2026-119977 lists the same 25 branch ranges. "
                 "Exposure arises during full-package core updates on affected releases."),
    },
}

KEV_CATALOG = "2026.11.18"
REVIEWED = "2026-11-19"
ALIAS = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_@./:-]{0,127}")
VERSION = re.compile(r"(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})(?:\.(0|[1-9][0-9]{0,3}))?")
MAX_BYTES = 16_384


def check_fields(obj, allowed):
    if not isinstance(obj, dict) or obj.keys() - set(allowed):
        raise ValueError("Unexpected evidence fields.")
    return obj


def alias(value):
    return value if isinstance(value, str) and ALIAS.fullmatch(value) else None


def release(value):
    """WordPress spells a branch's first release as x.y; x.y.0 is accepted as the same release."""
    if not isinstance(value, str):
        return None
    match = VERSION.fullmatch(value)
    if not match:
        return None
    major, minor, patch = match.groups()
    return (int(major), int(minor), int(patch or 0))


def spell(version):
    return f"{version[0]}.{version[1]}" if version[2] == 0 else ".".join(map(str, version))


def classify(profile, version):
    fixed = profile["fixed"].get(version[:2])
    if fixed is not None:
        if version < fixed:
            return "affected_version", spell(fixed), "The release falls in the vendor's affected range for its branch."
        return "vendor_fix_present", spell(fixed), "The release includes the vendor's fix for its branch."
    below = profile.get("not_affected_below")
    if below is not None and version < below:
        return "outside_affected_range", None, "The vendor states that releases before this range are not affected."
    unbackported = profile.get("affected_without_backport_below")
    if unbackported is not None and version < unbackported:
        return ("affected_version", spell(profile["fix_for_unbackported"]),
                "The CNA record lists this release as affected and its branch received no backport.")
    return "unknown", None, "This release line is outside the branches reviewed for this advisory."


def feature_status(profile, config, scope):
    conditions = check_fields(config.get("conditions", {}), profile["conditions"])
    if not profile["conditions"]:
        return "unknown", None
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
        "asset", "build", "ref", "version", "origin", "deployment_verified", "core_checksums_verified"))
    config = check_fields(request.get("applicability", {}), ("asset", "build", "ref", "conditions"))
    # Validate configuration evidence whether or not the inventory gate passes.
    conditions = check_fields(config.get("conditions", {}), profile["conditions"])
    if any(v is not None and type(v) is not bool for v in conditions.values()):
        raise ValueError("A condition must be true, false or null.")
    scope = {k: alias(inventory.get(k)) for k in ("asset", "build")}
    inv_ref = alias(inventory.get("ref"))
    status, fixed, detail = "unknown", None, "A referenced core version record from the deployed build is required."
    applicability, config_ref = "unknown", None
    parsed = None
    if all(scope.values()) and inv_ref and inventory.get("deployment_verified") is True:
        applicability, config_ref = feature_status(profile, config, scope)
        parsed = release(inventory.get("version"))
        if inventory.get("origin") != "upstream":
            detail = "A modified or host-maintained core requires the maintainer's own patch record."
        elif parsed is None:
            detail = "An exact stable WordPress release such as 7.1 or 7.1.4 is required."
        else:
            status, fixed, detail = classify(profile, parsed)
            if status in ("vendor_fix_present", "outside_affected_range") and inventory.get("core_checksums_verified") is not True:
                status, fixed, detail = "unknown", None, (
                    "A clean result needs core files verified against the wordpress.org checksums for this release.")
    return {
        "advisory": advisory, "vendor_advisory": profile["ghsa"], "product": "wordpress-core",
        "scope": scope, "version": spell(parsed) if parsed else None,
        "patch_status": status, "patch_reason": detail, "first_fixed_in_range": fixed,
        "applicability": applicability, "evidence_refs": {"inventory": inv_ref, "configuration": config_ref},
        "kev": {"date_added": profile["kev_date_added"], "catalog_version": KEV_CATALOG},
        "published": profile["published"], "reviewed": REVIEWED, "sources": profile["sources"],
        "limitations": ["Results concern the named advisory and the supplied build only.", profile["note"],
                        "Configuration evidence describes features. Proof of compromise needs separate evidence."],
    }


def unique_keys(pairs):
    obj = dict(pairs)
    if len(obj) != len(pairs):
        raise ValueError("Duplicate input key.")
    return obj


def reject_constant(token):
    raise ValueError(f"{token} is not valid JSON.")


def finite_float(text):
    value = float(text)
    if value != value or value in (float("inf"), float("-inf")):
        raise ValueError("Numbers must be finite.")
    return value


def main():
    try:
        raw = sys.stdin.buffer.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError("Input exceeds the supported size.")
        # RFC 8259: the body must be UTF-8 (one leading byte-order mark is accepted, as Windows
        # tools write one); NaN and Infinity are not JSON.
        text = raw.decode("utf-8-sig")
        result = review(json.loads(text, object_pairs_hook=unique_keys,
                                   parse_constant=reject_constant, parse_float=finite_float))
    except (ValueError, RecursionError):
        print(json.dumps({"error": "invalid_input", "detail": "Check the named advisory, scoped fields and input size."}))
        return 2
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
