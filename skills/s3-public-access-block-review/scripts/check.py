"""Compare saved bucket and effective-account S3 Block Public Access settings."""
import json
import re
import sys


FLAGS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
OPERATIONS = {"bucket": "s3api.get-public-access-block", "account": "s3control.get-public-access-block"}
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_./:@-]{0,127}")
SCOPE_KEYS = ("account", "bucket", "ownership_ref", "region", "snapshot", "bucket_type", "access_path")
MAX_BYTES = 32_768


def fields(record, allowed):
    if not isinstance(record, dict) or record.keys() - set(allowed):
        raise ValueError("Unexpected evidence fields.")
    return record


def alias(value):
    if value is not None and (not isinstance(value, str) or not IDENTIFIER.fullmatch(value)):
        raise ValueError("Use an opaque identifier.")
    return value


def unique(pairs):
    obj = dict(pairs)
    if len(obj) != len(pairs):
        raise ValueError("Duplicate key.")
    return obj


def observe(level, record, scope):
    if record is None:
        return {}, {"state": "missing", "ref": None}
    keys = ("account", "bucket", "region", "snapshot") if level == "bucket" else ("account", "region", "snapshot")
    fields(record, (*keys, "operation", "ref", "response", "error"))
    ref = alias(record.get("ref"))
    response = fields(record.get("response", {}), ("PublicAccessBlockConfiguration",))
    config = fields(response.get("PublicAccessBlockConfiguration", {}), FLAGS)
    if any(type(value) is not bool for value in config.values()):
        raise ValueError("A supplied S3 flag must be a JSON boolean.")
    if "error" in record and ("response" in record or not alias(record["error"])):
        raise ValueError("Use an error code or a response.")
    if record.get("operation") != OPERATIONS[level] or not ref or any(
            not scope[key] or record.get(key) != scope[key] for key in keys):
        return {}, {"state": "unmatched", "ref": None}
    if not config:
        return {}, {"state": "unavailable", "ref": ref}
    state = "complete" if len(config) == len(FLAGS) else "partial"
    return config, {"state": state, "ref": ref}


def review(data):
    fields(data, ("scope", "policy_ref", "required", "bucket_evidence", "account_evidence"))
    given_scope = fields(data.get("scope", {}), SCOPE_KEYS)
    scope = {key: alias(given_scope.get(key)) for key in SCOPE_KEYS}
    required = data.get("required", [])
    if not isinstance(required, list) or len(required) > len(FLAGS) or any(flag not in FLAGS for flag in required):
        raise ValueError("Use a list of recognized required flags.")
    if len(set(required)) != len(required):
        raise ValueError("Duplicate baseline flag.")
    policy_ref = alias(data.get("policy_ref"))
    supported = all(scope.values()) and scope["bucket_type"] == "general-purpose" and scope["access_path"] == "direct-bucket"

    bucket, bucket_record = observe("bucket", data.get("bucket_evidence"), scope)
    account, account_record = observe("account", data.get("account_evidence"), scope)
    combined = {}
    for flag in FLAGS:
        values = (bucket.get(flag), account.get(flag))
        if supported and True in values:
            combined[flag] = True
        elif supported and values == (False, False):
            combined[flag] = False
        else:
            combined[flag] = None

    gaps = [key for key in required if combined[key] is False]
    unverified = [key for key in required if combined[key] is None]
    status = "unknown"
    if policy_ref and required and supported:
        if gaps:
            status = "gap"
        elif not unverified:
            status = "pass"
    return {"scope": scope, "policy_ref": policy_ref, "required": required, "status": status,
            "combined_settings": combined, "disabled_required": gaps, "unverified_required": unverified,
            "evidence": {"bucket": bucket_record, "account": account_record}, "public_access": "unknown"}


def main():
    try:
        raw = sys.stdin.buffer.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError("Input too large.")
        result = review(json.loads(raw, object_pairs_hook=unique))
    except (ValueError, RecursionError):
        print(json.dumps({"error": "invalid_input"}))
        return 2
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
