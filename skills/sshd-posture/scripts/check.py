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
    the policy named this category (or its section) but in an unusable shape -- so
    the category must read unknown rather than silently pass. A category or section
    that is simply absent is no constraint; one that is present but null, or not a
    list of strings, is malformed (fail closed)."""
    if kind not in policy:
        return set(), False  # this kind is not constrained
    section = policy[kind]
    if not isinstance(section, dict):
        return set(), True   # present but not an object (null, string, ...)
    if category not in section:
        return set(), False  # this category is not constrained
    vals = section[category]
    if not isinstance(vals, list):
        return set(), True   # present but null / not a list -> unusable policy
    if not all(isinstance(v, str) for v in vals):
        return set(), True   # a non-string element -> unusable policy, read unknown
    return set(vals), False


def _category_verdict(record, category, forbidden, required):
    """Verdict for one category. ``forbidden`` is a positive detection across the
    captured direction name-lists -- a forbidden algorithm offered in ANY captured
    direction is a gap, even if the opposite direction was not captured.
    ``required`` is checked PER direction: a captured direction offering none of
    the required set is a gap (SSH negotiates the two directions independently), so
    a required algorithm present in only one direction is still a gap. Fails
    closed: when nothing above decided the category and a direction's name-list was
    not captured, it reads unknown rather than pass."""
    if record.get("kexinit_read") is not True:
        # No KEXINIT was fully read (false, absent, or non-boolean). A truncated
        # KEXINIT can leave partial name-lists in the record; they are not trusted.
        return "unknown"
    clean_directions = []  # directions whose every element was a string
    seen = set()           # every string name offered across captured directions
    incomplete = False     # a direction's name-list was absent from the record
    malformed = False      # a captured name-list carried a non-string element
    for field in _FIELDS[category]:
        vals = record.get(field)
        if not isinstance(vals, list):
            incomplete = True
            continue
        strings = [v for v in vals if isinstance(v, str)]
        seen.update(strings)
        if len(strings) == len(vals):
            clean_directions.append(set(strings))
        else:
            malformed = True
    if not seen and not clean_directions and not malformed:
        return "unknown"  # the category's name-list(s) were not captured at all
    # forbidden is a positive detection across every captured direction.
    if seen & forbidden:
        return "gap"
    # required is per direction: a fully-parsed direction offering none of the
    # required set is a definite gap, even when another direction was missing or
    # malformed. A malformed direction is not used to judge required -- its full
    # offer is unknown -- so it cannot by itself assert a required gap.
    if required and any(not (d & required) for d in clean_directions):
        return "gap"
    # a malformed or missing direction means a clean pass cannot be confirmed.
    if malformed or incomplete:
        return "unknown"
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

    # Policy-shape problems (a key outside the schema, e.g. "ciphers" for "cipher"
    # or "forbiden" for "forbidden"; a null / non-object section). These NEVER mask
    # a definite gap -- they only turn an otherwise-clean category or the overall
    # verdict into unknown, so a mistyped rule fails closed rather than reading a
    # false pass, while a well-formed rule that gaps still gaps.
    policy_problems = []
    unknown_top = sorted(k for k in policy if k not in ("forbidden", "required"))
    if unknown_top:
        policy_problems.append("policy names unknown keys: %s" % ", ".join(unknown_top))
    for _kind in ("forbidden", "required"):
        if _kind in policy and not isinstance(policy[_kind], dict):
            policy_problems.append("policy.%s is not an object" % _kind)
        elif isinstance(policy.get(_kind), dict):
            _unknown = sorted(k for k in policy[_kind] if k not in CATEGORIES)
            if _unknown:
                policy_problems.append("policy.%s names unknown categories: %s"
                                       % (_kind, ", ".join(_unknown)))

    per_category = {}
    for cat in CATEGORIES:
        forbidden, f_bad = _policy_set(policy, "forbidden", cat)
        required, r_bad = _policy_set(policy, "required", cat)
        if not forbidden and not required and not f_bad and not r_bad:
            continue  # the operator expressed no policy for this category
        # Judge with whatever is well-formed; a malformed half never masks a gap,
        # it only downgrades an otherwise-clean verdict to unknown.
        verdict = _category_verdict(record, cat, forbidden, required)
        if verdict != "gap" and (f_bad or r_bad):
            verdict = "unknown"
        per_category[cat] = verdict

    verdicts = list(per_category.values())
    if any(v == "gap" for v in verdicts):
        overall = "gap"
    elif policy_problems or not verdicts or any(v != "pass" for v in verdicts):
        overall = "unknown"
    else:
        overall = "pass"

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
    for problem in policy_problems:
        notes.append("%s (unusable, fails closed to unknown)" % problem)

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
