#!/usr/bin/env python3
"""Offline verdict for the TLS protocol-policy check.

Reads a saved observation record (produced by ``observe.py``) on stdin and
emits, for each policy version and overall, one of ``gap`` / ``pass`` /
``unknown``. Standard library only; Python 3.9+. It never opens a socket.

Only an exact server ``protocol_version`` alert (observation class
``version_refused``) counts as a refusal, and it counts as a verdict only when
some handshake in the same run completed. Everything else fails closed to
``unknown``.
"""
import json
import sys

VERSIONS = ("1.0", "1.1", "1.2", "1.3")


def _attempts_by_version(record):
    out = {}
    for a in record.get("attempts") or []:
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
    for a in record.get("attempts") or []:
        if a.get("class") == "negotiated":
            return True
    control = record.get("control") or {}
    return control.get("class") == "negotiated"


def _verdict_refuse(attempt, run_completed):
    if attempt is None:
        return "unknown"
    cls = attempt.get("class")
    if cls == "negotiated":
        return "gap"
    if cls == "version_refused":
        return "pass" if run_completed else "unknown"
    return "unknown"


def _verdict_accept(attempt, run_completed):
    if attempt is None:
        return "unknown"
    cls = attempt.get("class")
    if cls == "negotiated":
        return "pass"
    if cls == "version_refused":
        return "gap" if run_completed else "unknown"
    return "unknown"


def evaluate(record):
    if not isinstance(record, dict):
        return {"overall": "unknown",
                "reason": "observation record is not a JSON object",
                "per_version": {}}
    if record.get("error"):
        return {"overall": "unknown",
                "reason": "observation not usable: %s (%s)"
                          % (record.get("error"), record.get("reason", "")),
                "per_version": {}}
    policy = record.get("policy") or {}
    must_refuse = [str(v) for v in (policy.get("must_refuse") or [])]
    must_accept = [str(v) for v in (policy.get("must_accept") or [])]
    attempts = _attempts_by_version(record)
    run_completed = _run_completed(record)

    per_version = {}
    for v in must_refuse:
        per_version[v] = {"policy": "must_refuse",
                          "verdict": _verdict_refuse(attempts.get(v), run_completed)}
    for v in must_accept:
        per_version[v] = {"policy": "must_accept",
                          "verdict": _verdict_accept(attempts.get(v), run_completed)}

    verdicts = [d["verdict"] for d in per_version.values()]
    if not verdicts:
        overall = "unknown"
    elif any(x == "gap" for x in verdicts):
        overall = "gap"
    elif all(x == "pass" for x in verdicts):
        overall = "pass"
    else:
        overall = "unknown"

    return {
        "overall": overall,
        "per_version": per_version,
        "run_completed": run_completed,
        "target": record.get("target"),
        "authorization_ref": record.get("authorization_ref"),
        "limits": [
            "Covers one attempt per version, at the observed address, SNI and "
            "time: 'refused on this attempt' only.",
            "Other addresses behind the name, other ports and later changes are "
            "not covered.",
            "A server that refuses with a bare close or reset can only read "
            "unknown.",
        ],
    }


def main(argv=None):
    data = sys.stdin.read()
    try:
        record = json.loads(data)
    except json.JSONDecodeError as exc:
        print(json.dumps({"overall": "unknown",
                          "reason": "invalid JSON: %s" % exc,
                          "per_version": {}}, indent=2, sort_keys=True))
        return 0
    print(json.dumps(evaluate(record), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
