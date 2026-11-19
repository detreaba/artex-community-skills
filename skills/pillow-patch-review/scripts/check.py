"""Review the ImageCms extension loaded by a single Pillow image worker."""
import base64
import json
import re
import sys


ADVISORY = "CVE-2026-59205"
FIRST_FIX = "12.3.0"
# Published stable PyPI wheels reviewed on 2026-11-19.
AFFECTED = ("11.0.0", "11.1.0", "11.2.1", "11.3.0", "12.0.0", "12.1.0", "12.1.1", "12.2.0")
FIXED = (FIRST_FIX, "13.0.0")
SOURCES = (
    "https://github.com/python-pillow/Pillow/security/advisories/GHSA-9hw9-ch79-4vh6",
    "https://pillow.readthedocs.io/en/stable/releasenotes/12.3.0.html",
    "https://pypi.org/project/pillow/#history",
)
ALIAS = re.compile(r"[A-Za-z0-9][A-Za-z0-9_./:@-]{0,127}")
MEMBER = re.compile(r"PIL/_imagingcms(?:\.[A-Za-z0-9_-]+)*\.(?:so|pyd)")
SHA256 = re.compile(r"[a-fA-F0-9]{64}")
SCOPE = ("asset", "build", "worker")
MAX_BYTES = 16_384


def fields(obj, allowed):
    if not isinstance(obj, dict) or obj.keys() - set(allowed):
        raise ValueError("Unexpected evidence fields.")
    return obj


def alias(value):
    return value if isinstance(value, str) and ALIAS.fullmatch(value) else None


def assess(inventory, wheel, native, scope, refs):
    if not all(scope.values()) or not refs["inventory"] or inventory.get("deployment_verified") is not True:
        return "unknown", "A referenced inventory tied to one running worker is required."
    if inventory.get("origin") != "upstream" or not refs["wheel"] or wheel.get("pypi_verified") is not True:
        return "unknown", "Establish the worker's upstream origin and verify the original wheel against PyPI."
    name, version = wheel.get("name"), wheel.get("version")
    if not isinstance(name, str) or re.fullmatch("pillow", name, re.ASCII | re.IGNORECASE) is None:
        return "unknown", "The wheel must identify the Pillow distribution in its METADATA."
    if version != inventory.get("version") or version not in AFFECTED + FIXED:
        return "unknown", "The wheel and worker must agree on a stable release covered by this review."
    if not refs["native"] or any(native.get(key) != scope[key] for key in SCOPE):
        return "unknown", "The native module observation must identify this asset, build and worker."
    if native.get("module") != "PIL._imagingcms":
        return "unknown", "Identify the ImageCms extension loaded by this worker."
    binding = native.get("binding")
    if binding == "immutable_image":
        if native.get("immutable_start_verified") is not True:
            return "unknown", "Verify this worker started from the immutable image containing the observed extension."
    elif binding != "mapped_file":
        return "unknown", "Bind the extension bytes to the loaded file or to the worker's immutable startup image."
    member, digest = wheel.get("member"), native.get("sha256")
    if not isinstance(member, str) or MEMBER.fullmatch(member) is None:
        return "unknown", "Use the native PIL/_imagingcms member from the original wheel's RECORD."
    if not isinstance(digest, str) or SHA256.fullmatch(digest) is None:
        return "unknown", "A SHA-256 digest of the loaded native extension is required."
    record_hash = "sha256=" + base64.urlsafe_b64encode(bytes.fromhex(digest)).decode("ascii").rstrip("=")
    if wheel.get("record_hash") != record_hash:
        return "unknown", "The loaded extension digest and the wheel member's RECORD hash must agree."
    if version in AFFECTED:
        return "affected_version", "The loaded extension matches an upstream Pillow release covered by the advisory."
    return "vendor_fix_present", "The loaded extension matches a reviewed upstream Pillow release containing the fix."


def review(request):
    fields(request, ("advisory", "inventory", "wheel", "native"))
    if request.get("advisory") != ADVISORY:
        raise ValueError("Select the supported advisory.")
    inventory = fields(request.get("inventory", {}), SCOPE + ("ref", "origin", "deployment_verified", "version"))
    wheel = fields(request.get("wheel", {}), ("ref", "pypi_verified", "name", "version", "member", "record_hash"))
    native = fields(request.get("native", {}), SCOPE + ("ref", "module", "binding", "immutable_start_verified", "sha256"))
    scope = {key: alias(inventory.get(key)) for key in SCOPE}
    refs = {"inventory": alias(inventory.get("ref")), "wheel": alias(wheel.get("ref")), "native": alias(native.get("ref"))}
    status, reason = assess(inventory, wheel, native, scope, refs)
    return {
        "advisory": ADVISORY, "scope": scope, "patch_status": status, "patch_reason": reason,
        "version": inventory.get("version") if status != "unknown" else None,
        "first_fixed_release": FIRST_FIX if status != "unknown" else None, "applicability": "unknown",
        "evidence_refs": refs, "reviewed": "2026-11-19", "sources": list(SOURCES),
        "limitations": ["The result covers one worker. Application use of the affected operation needs separate evidence."],
    }


def unique_keys(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("Duplicate input key.")
    return result


def invalid_constant(value):
    raise ValueError("Invalid JSON constant.")


def main():
    try:
        raw = sys.stdin.buffer.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError("Input exceeds 16 KiB.")
        result = review(json.loads(raw, object_pairs_hook=unique_keys, parse_constant=invalid_constant))
    except (ValueError, RecursionError):
        print(json.dumps({"error": "invalid_input", "detail": "Check the advisory, evidence fields and input size."}))
        return 2
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
