"""Compare one recorded framework package with a named upstream security bulletin."""
import json
from pathlib import Path
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
RSC = "CVE-2025-55182"
RSC_OCTOBER = "CVE-2026-126187"
RSC_ADVISORIES = (RSC, RSC_OCTOBER)
RSC_PACKAGES = ("react-server-dom-parcel", "react-server-dom-turbopack", "react-server-dom-webpack")
CRAFT_ADVISORIES = "https://github.com/craftcms/cms/security/advisories/"
CRAFT_PACKAGE = {"ecosystem": "composer", "package": "craftcms/cms", "reviewed": "2026-11-20"}
# Stable tags in Packagist's livewire/livewire index on 2026-11-20.
# Each row gives the last published patch for minor 0, minor 1, and so on.
LIVEWIRE_LAST_PATCH = {
    0: (15, 6, 10, 21, 0, 3, 0, 4),
    1: (14, 0, 0, 9),
    2: (4, 4, 9, 18, 4, 5, 7, 2, 2, 0, 8, 3, 8),
    3: (10, 0, 6, 5, 12, 20, 4, 15, 11),
}
LIVEWIRE_AFFECTED_BETAS = {f"3.0.0-beta.{n}" for n in range(1, 12)}


def livewire_tag_ranges(majors):
    for major in majors:
        for minor, last in enumerate(LIVEWIRE_LAST_PATCH[major]):
            # 0.0 and 0.1 began at patch 1. Every other line began at 0.
            first = 1 if major == 0 and minor < 2 else 0
            yield (major, minor, first), (major, minor, last + 1)


# Both November 18 core advisories publish the same affected windows. Legacy
# branches can require an upgrade to reach the first supported fix.
DRUPAL_NOV_18 = {
    "ecosystem": "composer", "package": "drupal/core", "published": "2026-11-18",
    "windows": (
        ((8, 0, 0), (10, 6, 22), (10, 7, 0)),
        ((11, 0, 0), (11, 3, 22), (11, 4, 0)),
        ((11, 4, 0), (11, 4, 13), (11, 5, 0)),
    ),
    "conditions": (),
}
ADVISORIES = {
    RSC: {
        "ecosystem": "npm", "package": None, "published": "2025-12-03", "reviewed": "2026-11-20",
        "windows": (((19, 0, 0), (19, 0, 1), (19, 1, 0)), ((19, 1, 0), (19, 1, 2), (19, 2, 0)),
                    ((19, 2, 0), (19, 2, 1), (19, 3, 0))),
        "conditions": ("server_supports_react_server_components",),
        "sources": ["https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components",
                    "https://github.com/react/react/security/advisories/GHSA-fv66-9v8q-g76r"],
    },
    RSC_OCTOBER: {
        "ecosystem": "npm", "package": None, "published": "2026-10-14", "reviewed": "2026-11-20",
        "windows": (((19, 0, 0), (19, 0, 9), (19, 1, 0)), ((19, 1, 0), (19, 1, 10), (19, 2, 0)),
                    ((19, 2, 0), (19, 2, 9), (19, 3, 0)), ((19, 3, 0), (19, 3, 1), (19, 4, 0))),
        "conditions": ("server_supports_react_server_components", "publisher_response_condition_present"),
        "sources": ["https://github.com/react/react/security/advisories/GHSA-xqc2-xf4c-x3h3",
                    "https://www.cve.org/CVERecord?id=CVE-2026-126187"],
    },
    "CVE-2024-56145": {
        **CRAFT_PACKAGE, "published": "2024-12-18",
        "windows": (((3, 0, 0), (3, 9, 14), (4, 0, 0)), ((4, 0, 0), (4, 13, 2), (5, 0, 0)),
                    ((5, 0, 0), (5, 5, 2), (6, 0, 0))),
        "stable_3_floor": True, "conditions": ("php_register_argc_argv_enabled",),
        "sources": [CRAFT_ADVISORIES + "GHSA-2p6p-9rc9-62j9", "https://github.com/craftcms/cms/releases/tag/3.9.14"],
    },
    "CVE-2025-23209": {
        **CRAFT_PACKAGE, "published": "2025-01-18",
        "windows": (((4, 0, 0), (4, 13, 8), (5, 0, 0)), ((5, 0, 0), (5, 5, 8), (6, 0, 0))),
        "unresolved_range": ((5, 5, 5), (5, 5, 8)),
        "conditions": ("active_craft_key_compromise_confirmed",), "positive_evidence_only": True,
        "sources": [CRAFT_ADVISORIES + "GHSA-x684-96hh-833x", "https://github.com/craftcms/cms/releases/tag/5.5.8"],
    },
    "CVE-2025-32432": {
        **CRAFT_PACKAGE, "published": "2025-04-24",
        "windows": (((3, 0, 0), (3, 9, 15), (4, 0, 0)), ((4, 0, 0), (4, 14, 15), (5, 0, 0)),
                    ((5, 0, 0), (5, 6, 17), (6, 0, 0))),
        "conditions": (),
        "sources": [CRAFT_ADVISORIES + "GHSA-f3gw-9ww9-jmc3", "https://craftcms.com/knowledge-base/craft-cms-cve-2025-32432"],
    },
    "CVE-2025-54068": {
        "ecosystem": "composer", "package": "livewire/livewire", "published": "2025-07-17",
        "reviewed": "2026-11-20",
        "windows": tuple((start, (3, 6, 4), end) for start, end in livewire_tag_ranges((3,))),
        "outside": tuple(livewire_tag_ranges((0, 1, 2))),
        "conditions": ("livewire_component_mounted",),
        "additional_configuration_undisclosed": True,
        "sources": ["https://github.com/livewire/livewire/security/advisories/GHSA-29cq-5w36-x7w3",
                    "https://www.cve.org/CVERecord?id=CVE-2025-54068",
                    "https://github.com/livewire/livewire/releases/tag/v3.6.4",
                    "https://github.com/advisories/GHSA-29cq-5w36-x7w3"],
    },
    "CVE-2026-9082": {
        "ecosystem": "composer", "package": "drupal/core", "published": "2026-05-20", "reviewed": "2026-11-20",
        "published_core_only": True,
        "windows": (((8, 9, 0), None, (10, 0, 0)), ((10, 0, 0), (10, 4, 10), (10, 5, 0)),
                    ((10, 5, 0), (10, 5, 10), (10, 6, 0)), ((10, 6, 0), (10, 6, 9), (10, 7, 0)),
                    ((11, 0, 0), (11, 1, 10), (11, 2, 0)), ((11, 2, 0), (11, 2, 12), (11, 3, 0)),
                    ((11, 3, 0), (11, 3, 10), (11, 4, 0))),
        "conditions": ("serving_database_uses_postgresql",),
        "sources": ["https://www.drupal.org/sa-core-2026-004", "https://www.cve.org/CVERecord?id=CVE-2026-9082"],
    },
    "CVE-2026-132165": {
        **DRUPAL_NOV_18,
        "sources": ["https://www.drupal.org/sa-core-2026-017"],
    },
    "CVE-2026-132166": {
        **DRUPAL_NOV_18,
        "sources": ["https://www.drupal.org/sa-core-2026-018"],
    },
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
    if profile.get("published_core_only"):
        tag = ".".join(map(str, version))
        try:
            releases = Path(__file__).with_name("drupal-releases.txt").read_text(encoding="ascii").splitlines()
        except (OSError, UnicodeError):
            return "unknown", None, "The bundled Drupal release list is unavailable."
        if tag not in releases:
            return "unknown", None, "Verify the release against the publisher's Drupal core catalog."
    for start, fixed, end in profile["windows"]:
        if start <= version < end:
            if fixed is None:
                return "affected_version", None, "Drupal offers best-effort manual patches for these legacy branches. This major has no packaged fix."
            cutoff = ".".join(map(str, fixed))
            if version < fixed:
                return "affected_version", cutoff, "The release falls in the vendor's affected range."
            return "vendor_fix_present", cutoff, "The identified upstream release includes the named fix."
    if profile.get("published_core_only") or any(start <= version < end for start, end in profile.get("outside", ())):
        return "outside_affected_range", None, "This upstream release falls outside the documented affected range."
    return "unknown", None, "This release line is outside the branches reviewed by this checker."


def craft_patch(profile, raw):
    tag = raw.removeprefix("v") if isinstance(raw, str) else ""
    try:
        published = Path(__file__).with_name("craft-releases.txt").read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError):
        return None, ("unknown", None, "The bundled Craft release list is unavailable.")
    if tag not in published:
        return None, ("unknown", None, "Supply an exact deployed Craft tag covered by the reviewed release list.")

    # The only prereleases in the list are initial 3.x, 4.x and 5.x release candidates.
    base, _, candidate = tag.partition("-")
    version = tuple(map(int, base.split(".")))
    if candidate and version[0] == 3 and profile.get("stable_3_floor"):
        return tag, ("unknown", None, "The publisher starts the affected range at stable 3.0.0 and gives no determination for earlier Craft 3 candidates.")
    gap = profile.get("unresolved_range")
    if gap and gap[0] <= version < gap[1]:
        return tag, ("unknown", None, "The publisher ends the affected range before 5.5.5 and identifies 5.5.8 as fixed. Verify this intervening release separately.")
    return tag, classify(profile, version)


def feature_status(profile, config, scope):
    conditions = check_fields(config.get("conditions", {}), profile["conditions"])
    if not profile["conditions"]:
        # A package-only rule has no configuration verdict, even for a referenced empty record.
        return "unknown", None
    if any(v is not None and type(v) is not bool for v in conditions.values()):
        raise ValueError("A condition must be true, false or null.")
    ref = alias(config.get("ref"))
    if not ref or any(config.get(k) != v for k, v in scope.items()):
        return "unknown", None
    if any(conditions.get(k) is False for k in profile["conditions"]):
        if profile.get("positive_evidence_only"):
            return "unknown", ref
        return "conditions_absent", ref
    if profile.get("additional_configuration_undisclosed"):
        return "unknown", ref
    if all(conditions.get(k) is True for k in profile["conditions"]):
        return "conditions_present", ref
    return "unknown", ref


def rsc_patch(profile, inventory, serving, version):
    if (serving.get("source") != "server_resolver" or serving.get("contents_verified") is not True
            or not alias(serving.get("ref")) or serving["ref"] == inventory["ref"]
            or any(serving.get(k) != inventory.get(k) for k in ("asset", "build", "package", "version"))):
        return "unknown", None, "Reconcile the installed inventory with a separate verified server package observation."
    integrity = serving.get("integrity")
    if version is None or not isinstance(integrity, str):
        return "unknown", None, "Supply an exact published npm version and its verified archive integrity."
    entry = f"{inventory['package']} {inventory['version']} {integrity}"
    try:
        with Path(__file__).with_name("react-server-dom.sri").open(encoding="ascii") as releases:
            matched = any(line.rstrip("\n") == entry for line in releases)
    except (OSError, UnicodeError):
        matched = False
    if not matched or not any(start <= version < end for start, _, end in profile["windows"]):
        return "unknown", None, "The package, version and archive integrity do not match a reviewed npm release."
    return classify(profile, version)


def review(request):
    check_fields(request, ("advisory", "inventory", "applicability"))
    advisory = request.get("advisory")
    if not isinstance(advisory, str) or advisory not in ADVISORIES:
        raise ValueError("Select a supported advisory.")
    profile = ADVISORIES[advisory]
    inventory_fields = ("asset", "build", "ref", "ecosystem", "package", "version", "origin", "deployment_verified")
    if profile["package"] == "drupal/core":
        inventory_fields += ("serving_core_version",)
    if advisory in RSC_ADVISORIES:
        inventory_fields += ("serving_package",)
    inventory = check_fields(request.get("inventory", {}), inventory_fields)
    config = check_fields(request.get("applicability", {}), ("asset", "build", "ref", "conditions"))
    scope = {k: alias(inventory.get(k)) for k in ("asset", "build")}
    inv_ref = alias(inventory.get("ref"))
    package = inventory.get("package")
    if isinstance(package, str) and profile["ecosystem"] == "pypi":
        package = package.lower()
    expected_package = profile["package"]
    if advisory in RSC_ADVISORIES:
        expected_package = package if package in RSC_PACKAGES else None
        serving_package = check_fields(inventory.get("serving_package", {}),
                                       ("asset", "build", "ref", "package", "version", "source", "contents_verified", "integrity"))
    identity_matches = expected_package is not None and package == expected_package and inventory.get("ecosystem") == profile["ecosystem"]
    status, fixed, detail = "unknown", None, "A referenced inventory for the exact package in the deployed build is required."
    applicability, config_ref = "unknown", None
    parsed = None
    published_tag = None
    version_evidence = {}
    if identity_matches and all(scope.values()) and inv_ref and inventory.get("deployment_verified") is True:
        applicability, config_ref = feature_status(profile, config, scope)
        parsed = release(inventory.get("version"), profile["ecosystem"])
        serving = release(inventory.get("serving_core_version"), "composer") if package == "drupal/core" else None
        if package == "drupal/core" and parsed != serving:
            version_evidence = {"version_evidence": {"composer": ".".join(map(str, parsed)) if parsed else None,
                                                     "serving_core": ".".join(map(str, serving)) if serving else None}}
        if inventory.get("origin") != "upstream":
            detail = "The supplied package origin requires separate vendor or backport evidence."
        elif advisory in RSC_ADVISORIES:
            status, fixed, detail = rsc_patch(profile, inventory, serving_package, parsed)
        elif version_evidence:
            observations = (("Composer package", parsed), ("serving core", serving))
            flags = [f"The {source} falls in the affected range." for source, version in observations
                     if version is not None and classify(profile, version)[0] == "affected_version"]
            detail = " ".join(flags + ["Prioritize reconciling the deployment records."]) if flags else (
                "The Composer and serving core observations do not establish a matching release. Reconcile the deployment records."
            )
        elif package == "craftcms/cms":
            published_tag, (status, fixed, detail) = craft_patch(profile, inventory.get("version"))
            parsed = None
        elif parsed is None:
            detail = "An exact stable release from the deployed package is required."
            raw = inventory.get("version")
            if package == "livewire/livewire" and isinstance(raw, str):
                tag = raw.removeprefix("v")
                if tag in LIVEWIRE_AFFECTED_BETAS:
                    published_tag = tag
                    status, fixed = "affected_version", "3.6.4"
                    detail = "This published beta is in the affected range beginning at 3.0.0-beta.1."
        else:
            status, fixed, detail = classify(profile, parsed)
        if version_evidence:
            parsed = None
    refs = {"inventory": inv_ref, "configuration": config_ref}
    if advisory in RSC_ADVISORIES:
        same_scope = all(scope.values()) and all(serving_package.get(k) == v for k, v in scope.items())
        refs["serving_package"] = alias(serving_package.get("ref")) if same_scope else None
        if status == "unknown":
            parsed = None
    limitations = ["Results concern the named advisory and supplied build only.",
                   "Configuration evidence describes features. Actual disclosure or access requires separate evidence."]
    if profile.get("additional_configuration_undisclosed"):
        limitations.append("Livewire also requires a configuration the publisher did not identify. A mounted component alone leaves applicability unknown.")
    if advisory in RSC_ADVISORIES:
        limitations.append("The server resolution and installed-content match are operator attestations. "
                           "A framework's bundled copy and other React advisories require their own review.")
    if advisory == "CVE-2026-9082":
        limitations.append("The PostgreSQL condition concerns this Drupal core advisory. Review the separate Symfony and Twig dependency updates for every database.")
    if profile.get("positive_evidence_only"):
        limitations.append("Only a confirmed compromise of the active key establishes this condition. A missing incident record or key rotation alone leaves it unknown.")
    return {
        "advisory": advisory, "package": expected_package, "ecosystem": profile["ecosystem"],
        "scope": scope, "version": ".".join(map(str, parsed)) if parsed else published_tag, **version_evidence,
        "patch_status": status, "patch_reason": detail, "first_fixed_in_range": fixed,
        "applicability": applicability, "evidence_refs": refs,
        "published": profile["published"], "reviewed": profile.get("reviewed", REVIEWED), "sources": profile["sources"],
        "limitations": limitations,
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
