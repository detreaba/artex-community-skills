#!/usr/bin/env python3
"""Offline verdict for the sshd-posture check.

Reads a saved observation record (produced by ``observe.py``) on stdin and
emits, per category and overall, one of ``gap`` / ``pass`` / ``unknown``.
Standard library only; Python 3.9+. It never opens a socket.

The verdict rests on the algorithms the server *offered* in its KEXINIT and on
the SSH protocol version. The software/version string is self-reported, so it is
recorded as advisory only and never drives a verdict. Everything fails closed to
``unknown``, including malformed input.
"""
import json
import sys

CATEGORIES = ("kex", "hostkey", "cipher", "mac")
_FIELDS = {
    "kex": ("kex_algorithms",),
    "hostkey": ("server_host_key_algorithms",),
    "cipher": ("encryption_c2s", "encryption_s2c"),
    "mac": ("mac_c2s", "mac_s2c"),
}


def _offered(record, category):
    """The set of algorithms offered for a category, or None if the observation
    did not capture it (so the category reads unknown)."""
    if not record.get("kexinit_read"):
        return None
    out = set()
    seen = False
    for field in _FIELDS[category]:
        vals = record.get(field)
        if isinstance(vals, list):
            seen = True
            out.update(str(v) for v in vals)
    return out if seen else None


def _policy_set(policy, kind, category):
    """Return (algorithms, malformed): the policy set for a category, and whether
    the policy named this category but in an unusable shape -- so the category
    must read unknown rather than silently pass."""
    section = policy.get(kind)
    if section is None:
        return set(), False
    if not isinstance(section, dict):
        return set(), True
    vals = section.get(category)
    if vals is None:
        return set(), False
    if not isinstance(vals, list):
        return set(), True
    return set(str(v) for v in vals), False


def _category_verdict(offered, forbidden, required):
    if offered is None:
        return "unknown"
    if offered & forbidden:
        return "gap"
    if required and not (offered & required):
        return "gap"
    return "pass"


def _protocol_verdict(record):
    proto = record.get("protocol")
    if not isinstance(proto, str) or not proto:
        return "unknown"
    # SSH protocol 1.x -- including the "1.99" back-compatibility banner -- is
    # deprecated and a gap. Only "2.0" is a pass.
    return "gap" if proto.startswith("1") else "pass"


def evaluate(record):
    if not isinstance(record, dict):
        return {"overall": "unknown",
                "reason": "observation record is not a JSON object",
                "per_category": {}}
    if "error" in record:
        return {"overall": "unknown",
                "reason": "observation not usable: %s (%s)"
                          % (record.get("error"), record.get("reason", "")),
                "per_category": {}}
    policy = record.get("policy")
    if not isinstance(policy, dict):
        policy = {}

    per_category = {}
    for cat in CATEGORIES:
        forbidden, f_bad = _policy_set(policy, "forbidden", cat)
        required, r_bad = _policy_set(policy, "required", cat)
        if f_bad or r_bad:
            per_category[cat] = "unknown"  # policy named this category but is malformed
            continue
        if not forbidden and not required:
            continue  # the operator expressed no policy for this category
        per_category[cat] = _category_verdict(_offered(record, cat), forbidden, required)
    # SSH protocol version is always evaluated; v1 is universally deprecated.
    per_category["protocol"] = _protocol_verdict(record)

    verdicts = list(per_category.values())
    if not verdicts:
        overall = "unknown"
    elif any(v == "gap" for v in verdicts):
        overall = "gap"
    elif all(v == "pass" for v in verdicts):
        overall = "pass"
    else:
        overall = "unknown"

    return {
        "overall": overall,
        "per_category": per_category,
        "software": record.get("software"),
        "banner": record.get("banner"),
        "target": record.get("target"),
        "authorization_ref": record.get("authorization_ref"),
        "limits": [
            "Offered algorithms only -- not what a specific client negotiates, "
            "nor sshd_config beyond what the offer reveals, nor auth policy.",
            "The software/version string is self-reported and advisory; the "
            "verdict rests on the offered algorithms and the protocol version.",
            "Observed at one address and time; a category the observation did "
            "not capture reads unknown.",
        ],
    }


def main(argv=None):
    try:
        data = sys.stdin.read()
    except (UnicodeDecodeError, OSError) as exc:
        print(json.dumps({"overall": "unknown",
                          "reason": "could not read stdin: %s" % exc,
                          "per_category": {}}, indent=2, sort_keys=True))
        return 0
    try:
        record = json.loads(data)
    except (ValueError, RecursionError) as exc:
        print(json.dumps({"overall": "unknown",
                          "reason": "invalid JSON: %s" % exc,
                          "per_category": {}}, indent=2, sort_keys=True))
        return 0
    try:
        result = evaluate(record)
    except Exception as exc:  # fail closed: any unexpected shape -> unknown
        result = {"overall": "unknown",
                  "reason": "could not evaluate observation: %s" % exc,
                  "per_category": {}}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
