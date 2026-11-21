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


def _is_name(tok):
    """True if tok is a well-formed SSH algorithm name (RFC 4251 Sec. 6): a
    non-empty string of printable US-ASCII with no whitespace and no comma, at most
    64 characters. The local/vendor form ``name@domainname`` has exactly one
    at-sign, a non-empty local part, and a fully-qualified domain name after it (at
    least two non-empty dot-separated labels); a name with no at-sign contains no
    at-sign at all. A token that is padded, over-long, or @-malformed is NOT a valid
    name -- it must not be exact-matched as if it were a distinct algorithm (which
    would let it slip a forbidden set)."""
    if not (isinstance(tok, str) and 1 <= len(tok) <= 64
            and "," not in tok
            and all("\x21" <= c <= "\x7e" for c in tok)):
        return False
    if "@" in tok:
        local, _, domain = tok.partition("@")
        if local == "" or "@" in domain:
            return False
        # the domain MUST be a fully-qualified domain name (RFC 4251 Sec. 6 ->
        # RFC 1034): at least two non-empty dot-separated labels.
        labels = domain.split(".")
        return len(labels) >= 2 and all(lbl != "" for lbl in labels)
    return True


def _policy_set(policy, kind, category):
    """Return (algorithms, malformed): the policy set for a category, and whether
    the policy named this category (or its section) but in an unusable shape -- so
    the category must read unknown rather than silently pass. A category or section
    that is simply absent is no constraint; one that is present but null, not a
    list, or carries an element that is not a well-formed name, is malformed (fail
    closed), though well-formed names in it are kept so a forbidden token still
    gaps."""
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
    names = [v for v in vals if _is_name(v)]
    # Keep the well-formed names so a forbidden token still gaps even when a
    # sibling element is malformed; the malformed flag only downgrades a non-gap.
    return set(names), len(names) != len(vals)


def _category_verdict(record, category, forbidden, required,
                      forbidden_partial=False, required_partial=False):
    """Verdict for one category. ``forbidden`` is a positive detection across the
    captured direction name-lists -- a forbidden algorithm offered in ANY captured
    direction is a gap, even if the opposite direction was not captured and even if
    part of the forbidden policy list was unreadable (a hit on a well-formed token
    is definite). ``required`` is checked PER direction on the well-formed names of
    directions whose elements are all strings: such a direction offering none of the
    required set is a PROVABLE miss -> gap (a non-well-formed string token can never
    equal a well-formed required name), unless the required policy list is partial.
    Only a non-string element makes a direction unreadable (can't judge required).
    Fails closed: absent a definite gap, a non-standard token (which may disguise a
    forbidden name), an unreadable or missing direction, or a partial policy reads
    unknown rather than pass; a definite gap always wins."""
    if record.get("kexinit_read") is not True:
        # No KEXINIT was fully read (false, absent, or non-boolean). A truncated
        # KEXINIT can leave partial name-lists in the record; they are not trusted.
        return "unknown"
    clean_directions = []  # directions whose elements are all strings (judge required)
    seen = set()           # well-formed names offered across captured directions
    incomplete = False     # a direction's name-list was absent from the record
    unreadable = False     # a non-string element -> that direction cannot be read
    nonstandard = False    # a string token that is not a well-formed name
    for field in _FIELDS[category]:
        vals = record.get(field)
        if not isinstance(vals, list):
            incomplete = True
            continue
        valid = [v for v in vals if _is_name(v)]
        seen.update(valid)
        if not all(isinstance(v, str) for v in vals):
            unreadable = True  # a non-string element: the offer cannot be read,
            continue           # so this direction cannot judge required
        if len(valid) != len(vals):
            nonstandard = True  # a string token that is not a well-formed name
        clean_directions.append(set(valid))
    if not seen and not clean_directions and not nonstandard and not unreadable:
        return "unknown"  # the category's name-list(s) were not captured at all
    # 1. forbidden: a well-formed forbidden name offered in any captured direction
    #    is a definite gap (even if part of the forbidden policy list was unreadable).
    if seen & forbidden:
        return "gap"
    # 2. required: a direction whose elements are all strings but offers none of the
    #    required set is a PROVABLE miss -> gap. A non-well-formed string token can
    #    never equal a well-formed required name, so it does not make the miss
    #    unprovable; only a non-string (unreadable) direction or a partial required
    #    policy does, and those are excluded here.
    if required and not required_partial and \
            any(not (d & required) for d in clean_directions):
        return "gap"
    # 3. no definite gap. A clean pass cannot be confirmed when a token was
    #    non-standard (it may disguise a forbidden algorithm), a direction was
    #    unreadable or missing, or the policy was partial -> unknown.
    if nonstandard or unreadable or incomplete or forbidden_partial or required_partial:
        return "unknown"
    return "pass"


def evaluate(record):
    if not isinstance(record, dict):
        return {"overall": "unknown",
                "reason": "observation record is not a JSON object",
                "per_category": {}}
    # A present "error" field -- truthy (as observe.py's _fail writes, "invalid_input")
    # or a non-standard falsy (null / false / "") -- is a record anomaly: it downgrades
    # an otherwise-clean verdict to unknown (fail-closed) but NEVER masks a captured
    # gap. The kexinit_read gate below means name-lists are judged only when the KEXINIT
    # was fully parsed, so a forbidden algorithm present under an error is a real gap,
    # not a guess. A real _fail record carries no policy and no name-lists, so there is
    # nothing to judge and it reads unknown regardless.
    error_present = "error" in record
    error_value = record.get("error")
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
        # it only downgrades an otherwise-clean verdict to unknown (handled inside
        # _category_verdict via the partial flags).
        per_category[cat] = _category_verdict(record, cat, forbidden, required,
                                              forbidden_partial=f_bad,
                                              required_partial=r_bad)

    verdicts = list(per_category.values())
    if any(v == "gap" for v in verdicts):
        overall = "gap"
    elif error_present or policy_problems or not verdicts \
            or any(v != "pass" for v in verdicts):
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
    if error_present:
        _why = record.get("reason")
        notes.append("record reports error %r%s; a clean verdict is downgraded to "
                     "unknown, but a captured gap still stands"
                     % (error_value, (": %s" % _why) if _why else ""))

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
