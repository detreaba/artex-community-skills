#!/usr/bin/env python3
"""Offline verdict for the sshd-posture check.

Reads a saved observation record (produced by ``observe.py``) on stdin and
emits, per category and overall, one of ``gap`` / ``pass`` / ``unknown``.
Standard library only; Python 3.9+. It never opens a socket.

The verdict rests only on the algorithms the server *offered* in its KEXINIT.
The identification string -- both the software name and the SSH protocol token --
is self-reported and can be forged, so it is recorded as advisory only and never
drives a verdict (confirming SSH-1 support would need an SSH-1 handshake, which
this check does not perform). Everything fails closed to ``unknown``.
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


def _category_verdict(record, category, forbidden, required):
    """Verdict for one category. ``forbidden`` is checked across the union of the
    category's direction name-lists (any direction offering a forbidden algorithm
    is a gap). ``required`` is checked PER direction (each direction must offer a
    required algorithm), so a required algorithm present in only one direction is
    still a gap -- SSH negotiates the two directions independently. Fails closed:
    a direction whose name-list was not captured reads unknown."""
    if not record.get("kexinit_read"):
        return "unknown"
    per_direction = []
    for field in _FIELDS[category]:
        vals = record.get(field)
        if not isinstance(vals, list):
            return "unknown"
        per_direction.append(set(str(v) for v in vals))
    union = set().union(*per_direction)
    if union & forbidden:
        return "gap"
    if required and any(not (direction & required) for direction in per_direction):
        return "gap"
    return "pass"


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
        per_category[cat] = _category_verdict(record, cat, forbidden, required)

    verdicts = list(per_category.values())
    if not verdicts:
        overall = "unknown"
    elif any(v == "gap" for v in verdicts):
        overall = "gap"
    elif all(v == "pass" for v in verdicts):
        overall = "pass"
    else:
        overall = "unknown"

    notes = [
        "Offered algorithms only -- not what a specific client negotiates, nor "
        "sshd_config beyond what the offer reveals, nor auth policy.",
        "The identification string (software and protocol token) is self-reported "
        "and advisory; the verdict rests on the offered algorithms.",
        "A category the observation did not capture reads unknown.",
    ]
    proto = record.get("protocol")
    if isinstance(proto, str) and proto.startswith("1"):
        notes.append("advisory: the identification string declares SSH protocol "
                     "%s; SSH-1 support is not confirmed here (it would need an "
                     "SSH-1 handshake, which this check does not perform)." % proto)

    return {
        "overall": overall,
        "per_category": per_category,
        "protocol": proto,
        "software": record.get("software"),
        "banner": record.get("banner"),
        "target": record.get("target"),
        "authorization_ref": record.get("authorization_ref"),
        "notes": notes,
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
