"""Review a saved Zyxel USG FLEX H running-firmware record for one physical appliance."""
import json
import re
import sys


ADVISORY = "CVE-2025-1731"
BULLETIN = ("https://www.zyxel.com/global/en/support/security-advisories/"
            "zyxel-security-advisory-for-incorrect-permission-assignment-and-"
            "improper-privilege-management-vulnerabilities-in-usg-flex-h-series-firewalls-04-22-2025")
MODEL_CODES = {
    "USG FLEX 50H": "ACLO", "USG FLEX 50HP": "ACLP",
    "USG FLEX 100H": "ABXF", "USG FLEX 100HP": "ACII",
    "USG FLEX 200H": "ABWV", "USG FLEX 200HP": "ABXE",
    "USG FLEX 500H": "ABZH", "USG FLEX 700H": "ABZI",
}
# Each bulletin's table lists one of these two observed model groups.
ORIGINAL_CODES = frozenset(("ABXF", "ACII", "ABWV", "ABXE", "ABZH", "ABZI"))
EIGHT_CODES = ORIGINAL_CODES | {"ACLO", "ACLP"}
# (uOS trunk, patch) -> (Zyxel release table, hardware codes in that table).
RELEASE_NOTES = {
    (10, 1): (19966, ORIGINAL_CODES), (20, 0): (22418, ORIGINAL_CODES),
    (20, 2): (23502, ORIGINAL_CODES), (21, 0): (24413, ORIGINAL_CODES),
    (30, 0): (26418, ORIGINAL_CODES), (30, 1): (26795, ORIGINAL_CODES),
    (31, 0): (27878, ORIGINAL_CODES), (32, 0): (28988, EIGHT_CODES),
    (35, 0): (30179, EIGHT_CODES), (35, 1): (30404, EIGHT_CODES),
    (35, 2): (30611, EIGHT_CODES), (36, 0): (30935, EIGHT_CODES),
    (37, 0): (32050, EIGHT_CODES), (37, 1): (32407, EIGHT_CODES),
    (38, 0): (32686, EIGHT_CODES), (39, 0): (33654, EIGHT_CODES),
    (40, 0): (34340, EIGHT_CODES),
}
ALIAS = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,127}")
FIRMWARE = re.compile(r"V?(?P<major>[0-9]+)\.(?P<trunk>[0-9]{2}) ?\((?P<code>[A-Z]{4})\."
                      r"(?P<patch>0|[1-9][0-9]?)\)(?P<suffix>[A-Za-z0-9_-]*)")
LIMIT = 16_384


def alias(value):
    return value if isinstance(value, str) and ALIAS.fullmatch(value) else None


def fields(record, allowed):
    if not isinstance(record, dict) or record.keys() - allowed:
        raise ValueError("Unexpected input fields.")
    return record


def version_fields(row):
    value = row.get("Version")
    return FIRMWARE.fullmatch(value) if isinstance(value, str) else None


def classify(rows):
    running = [row for row in rows if row.get("Status") == "Running"]
    if len(running) != 1 or any(row.get("Status") not in ("Running", "Standby") for row in rows):
        return {"patch_reason": "Supply one unambiguous Running firmware row from the named physical unit."}
    row = running[0]
    model = row.get("Model")
    if not isinstance(model, str) or model not in MODEL_CODES:
        return {"patch_reason": "This model is outside the reviewed USG FLEX H hardware."}
    if any(other.get("Model") != model for other in rows):
        return {"patch_reason": "The firmware rows disagree on the physical appliance model."}
    code = MODEL_CODES[model]
    match = version_fields(row)
    if not match or match["major"] != "1" or match["code"] != code or match["suffix"] not in ("", "C0"):
        return {"patch_reason": "Supply the complete running production firmware version for this model code."}
    for other in rows:
        if other["Status"] == "Standby":
            staged = version_fields(other)
            if not staged or staged["code"] != code:
                return {"patch_reason": "Reconcile the Standby version and hardware code with the named appliance."}
    trunk, patch = int(match["trunk"]), int(match["patch"])
    release = RELEASE_NOTES.get((trunk, patch))
    if not release or code not in release[1]:
        return {"patch_reason": "This model and firmware build are absent from the reviewed release tables."}
    first_fixed = f"V1.32({code}.0)C0"
    if trunk < 20:
        status, reason = "outside_affected_range", "The running release predates the vendor's affected range."
        first_fixed = None
    elif trunk < 32:
        status, reason = "affected_version", "The running production firmware falls in the vendor's affected range."
    else:
        status, reason = "vendor_fix_present", "The running production firmware includes the named advisory fix."
    return {"patch_status": status, "patch_reason": reason, "model": model, "observed_version": row["Version"],
            "first_fixed_on_branch": first_fixed, "sources": [BULLETIN, f"https://community.zyxel.com/en/discussion/{release[0]}"]}


def review(request):
    fields(request, {"advisory", "asset", "build", "inventory"})
    if request.get("advisory") != ADVISORY:
        raise ValueError("Unsupported advisory.")
    scope = {key: alias(request.get(key)) for key in ("asset", "build")}
    record = fields(request.get("inventory", {}), {
        "asset", "build", "ref", "origin", "origin_ref", "deployment_verified", "source",
        "firmware_status", "cloud_latest_version",
    })
    rows = record.get("firmware_status", [])
    if not isinstance(rows, list):
        raise ValueError("Firmware Status must be a list.")
    for row in rows:
        fields(row, {"Status", "Model", "Version"})
    ref, origin_ref = alias(record.get("ref")), alias(record.get("origin_ref"))
    if (not all(scope.values()) or not ref or record.get("deployment_verified") is not True
            or any(record.get(key) != value for key, value in scope.items())):
        ref, origin_ref = None, None
        result = {"patch_reason": "A referenced running inventory for this physical unit and boot is required."}
    elif record.get("source") != "firmware_management":
        result = {"patch_reason": "Supply the Firmware Status table from this unit's Firmware Management screen."}
    elif record.get("origin") != "upstream" or not origin_ref:
        result = {"patch_reason": "Establish Zyxel production firmware provenance for the currently running image."}
    else:
        result = classify(rows)
    return {"advisory": ADVISORY, "product": "Zyxel USG FLEX H", "scope": scope,
            "evidence_refs": {"inventory": ref, "origin": origin_ref}, "model": None, "observed_version": None,
            "first_fixed_on_branch": None, "patch_status": "unknown", "applicability": "unknown",
            "reviewed": "2026-11-20", "sources": [BULLETIN], **result}


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
