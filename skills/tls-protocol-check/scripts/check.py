#!/usr/bin/env python3
"""Offline verdict for the TLS protocol-policy check.

Reads a saved observation record (produced by ``observe.py``) on stdin and
emits, for each policy version and overall, one of ``gap`` / ``pass`` /
``unknown``. Standard library only; Python 3.9+. It never opens a socket.

Only an exact server ``protocol_version`` alert (observation class
``version_refused``) counts as a refusal, and it counts as a verdict only when
some handshake in the same run completed. Everything else fails closed to
``unknown`` — including malformed input: the entry point never crashes to a
clean exit, it returns ``unknown``.
"""
import json
import sys

# Map a negotiated version string (ssl.SSLSocket.version()) back to a policy token.
_NEGOTIATED_TO_VERSION = {
    "TLSv1": "1.0", "TLSv1.1": "1.1", "TLSv1.2": "1.2", "TLSv1.3": "1.3",
}


def _attempts_by_version(record):
    out = {}
    attempts = record.get("attempts")
    if not isinstance(attempts, list):
        return out
    for a in attempts:
        if isinstance(a, dict):
            v = a.get("version")
            if v is not None:
                out[str(v)] = a
    return out


def _run_completed(record):
    """True when at least one handshake in the run negotiated a version.

    Without a single completed handshake we cannot tell a server that refuses
    old TLS by policy from one that is down, filtered, or not speaking TLS, so
    a ``version_refused`` reading is not yet evidence of anything.
    """
    attempts = record.get("attempts")
    if isinstance(attempts, list):
        for a in attempts:
            if isinstance(a, dict) and a.get("class") == "negotiated":
                return True
    control = record.get("control")
    return isinstance(control, dict) and control.get("class") == "negotiated"


def _verdict_refuse(attempt, version, run_completed):
    if not isinstance(attempt, dict):
        return "unknown"
    cls = attempt.get("class")
    if cls == "negotiated":
        # A gap only when the handshake actually negotiated this version; a
        # completed handshake that landed on some other version is covered by
        # the run-wide negotiated-version scan in evaluate().
        return "gap" if _NEGOTIATED_TO_VERSION.get(attempt.get("negotiated")) == version else "unknown"
    if cls == "version_refused":
        return "pass" if run_completed else "unknown"
    return "unknown"


def _verdict_accept(attempt, version, run_completed):
    if not isinstance(attempt, dict):
        return "unknown"
    cls = attempt.get("class")
    if cls == "negotiated":
        # A pass only when this exact version was negotiated.
        return "pass" if _NEGOTIATED_TO_VERSION.get(attempt.get("negotiated")) == version else "unknown"
    if cls == "version_refused":
        return "gap" if run_completed else "unknown"
    return "unknown"


def _combine(verdicts):
    """Conservative merge for a version that carries more than one obligation:
    a gap anywhere wins, then any unknown, and only an all-pass is a pass. This
    keeps a negotiated must-refuse version a gap even when the same version is
    (contradictorily) also listed as must-accept."""
    if "gap" in verdicts:
        return "gap"
    if "unknown" in verdicts:
        return "unknown"
    return "pass"


def _version_list(policy, key):
    raw = policy.get(key)
    if not isinstance(raw, list):
        return []
    return [str(v) for v in raw]


def evaluate(record):
    if not isinstance(record, dict):
        return {"overall": "unknown",
                "reason": "observation record is not a JSON object",
                "per_version": {}}
    if "error" in record:
        return {"overall": "unknown",
                "reason": "observation not usable: %s (%s)"
                          % (record.get("error"), record.get("reason", "")),
                "per_version": {}}
    policy = record.get("policy")
    if not isinstance(policy, dict):
        policy = {}
    must_refuse = _version_list(policy, "must_refuse")
    must_accept = _version_list(policy, "must_accept")
    attempts = _attempts_by_version(record)
    run_completed = _run_completed(record)

    per_version = {}
    contradictory = []
    # One entry per distinct version; a version in both lists gets both
    # obligations, merged conservatively, so the must-refuse check can never be
    # silently overwritten by the must-accept check.
    for v in dict.fromkeys(must_refuse + must_accept):
        roles = []
        verdicts = []
        if v in must_refuse:
            roles.append("must_refuse")
            verdicts.append(_verdict_refuse(attempts.get(v), v, run_completed))
        if v in must_accept:
            roles.append("must_accept")
            verdicts.append(_verdict_accept(attempts.get(v), v, run_completed))
        if len(roles) > 1:
            contradictory.append(v)
        per_version[v] = {"policy": "+".join(roles), "verdict": _combine(verdicts)}

    # Any completed handshake -- a dedicated attempt or the full-range control --
    # that negotiated a must-refuse version is direct evidence the server accepts
    # that version, so it is a gap wherever the evidence appears.
    negotiated = set()
    for a in (record.get("attempts") or []):
        if isinstance(a, dict) and a.get("class") == "negotiated":
            negotiated.add(_NEGOTIATED_TO_VERSION.get(a.get("negotiated")))
    control = record.get("control")
    if isinstance(control, dict) and control.get("class") == "negotiated":
        negotiated.add(_NEGOTIATED_TO_VERSION.get(control.get("negotiated")))
    for cv in negotiated:
        if cv in must_refuse:
            entry = per_version.get(cv) or {"policy": "must_refuse", "verdict": "gap"}
            entry["verdict"] = "gap"
            per_version[cv] = entry

    verdicts = [d["verdict"] for d in per_version.values()]
    if not verdicts:
        overall = "unknown"
    elif any(x == "gap" for x in verdicts):
        overall = "gap"
    elif all(x == "pass" for x in verdicts):
        overall = "pass"
    else:
        overall = "unknown"

    notes = [
        "Covers one attempt per version, at the observed address, SNI and time: "
        "'refused on this attempt' only.",
        "Other addresses behind the name, other ports and later changes are not "
        "covered.",
        "A server that refuses with a bare close or reset can only read unknown.",
    ]
    if contradictory:
        notes.append(
            "Contradictory policy: version(s) %s listed as both must_refuse and "
            "must_accept; resolved conservatively (a negotiated such version is a "
            "gap)." % ", ".join(contradictory))

    return {
        "overall": overall,
        "per_version": per_version,
        "run_completed": run_completed,
        "target": record.get("target"),
        "authorization_ref": record.get("authorization_ref"),
        "limits": notes,
    }


def main(argv=None):
    try:
        data = sys.stdin.read()
    except (UnicodeDecodeError, OSError) as exc:
        print(json.dumps({"overall": "unknown",
                          "reason": "could not read stdin: %s" % exc,
                          "per_version": {}}, indent=2, sort_keys=True))
        return 0
    try:
        record = json.loads(data)
    except (ValueError, RecursionError) as exc:
        print(json.dumps({"overall": "unknown",
                          "reason": "invalid JSON: %s" % exc,
                          "per_version": {}}, indent=2, sort_keys=True))
        return 0
    try:
        result = evaluate(record)
    except Exception as exc:  # fail closed: any unexpected shape -> unknown
        result = {"overall": "unknown",
                  "reason": "could not evaluate observation: %s" % exc,
                  "per_version": {}}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
