"""Compare a redacted authorization policy with CI observations for one deployment."""

import json
import re
import sys
from collections import defaultdict


CONTEXT = ("role", "tenant", "ownership", "resource", "operation")
ALIAS = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,95}\Z", re.ASCII)
MAX_BYTES = 1 << 20


def fields(value, allowed):
    if not isinstance(value, dict) or value.keys() - set(allowed):
        raise ValueError("Unexpected evidence object or field.")


def alias(value):
    if value is None or value == "":
        return None
    if not isinstance(value, str) or not ALIAS.fullmatch(value):
        raise ValueError("Use short redacted identifiers.")
    return value


def index(rows, observed):
    if not isinstance(rows, list) or len(rows) > 128:
        raise ValueError("Supply at most 128 rows of each type.")
    result = defaultdict(list)
    for row in rows:
        fields(row, ("case", "context", "asset", "build", "run", "ref", "actual")
               if observed else ("case", "context", "expected"))
        case = row.get("case")
        if type(case) is not int or not 1 <= case <= 999999:
            raise ValueError("A case number must be an integer between 1 and 999999.")
        context = row.get("context", {})
        fields(context, CONTEXT)
        identity = tuple(alias(context.get(key)) for key in CONTEXT)
        decision = row.get("actual" if observed else "expected")
        if decision not in (None, "allow", "deny"):
            raise ValueError("Decisions must be allow or deny.")
        if observed:
            run = row.get("run")
            if run not in (None, "completed", "skipped", "error"):
                raise ValueError("Unrecognized run state.")
            result[case].append((alias(row.get("asset")), alias(row.get("build")),
                                 identity, decision, run, alias(row.get("ref"))))
        else:
            result[case].append((identity, decision))
    return result


def decision(asset, build, policy_ref, expected_rows, observed_rows):
    if not (asset and build and policy_ref):
        return "unknown", "The asset, build and policy reference are required."
    if len(set(expected_rows)) != 1:
        return "unknown", "Provide one unambiguous policy expectation for this case."
    context, expected = expected_rows[0]
    if None in context or expected is None:
        return "unknown", "The expected decision or policy context is incomplete."
    if not observed_rows:
        return "unknown", "No observation matches this asset, build and case."
    values = set()
    for _, _, actual_context, actual, run, ref in observed_rows:
        if run != "completed" or not ref or not actual:
            return "unknown", "A matching observation is incomplete or lacks a reference."
        if context != actual_context:
            return "unknown", "The observed and expected case contexts differ."
        values.add(actual)
    if len(values) != 1:
        return "unknown", "The matching observations disagree."
    if expected in values:
        return "pass", "The observed decision matches the expected decision."
    return "gap", "The observed decision differs from the expected decision."


def review(data):
    fields(data, ("asset", "build", "policy_ref", "expectations", "observations"))
    asset = alias(data.get("asset"))
    build = alias(data.get("build"))
    policy_ref = alias(data.get("policy_ref"))
    policies = index(data.get("expectations", []), False)
    observations = index(data.get("observations", []), True)
    checks = []
    for case in sorted(policies.keys() | observations.keys()):
        matching = [row for row in observations[case] if row[:2] == (asset, build)]
        status, summary = decision(asset, build, policy_ref, policies[case], matching)
        checks.append({"id": f"AUTH-{case}", "status": status, "summary": summary,
                       "observation_refs": sorted({row[5] for row in matching if row[5]})})
    if not checks:
        checks.append({"id": "AUTH-coverage", "status": "unknown",
                       "summary": "No policy cases or observations were supplied.", "observation_refs": []})
    return {"asset": asset, "build": build, "policy_ref": policy_ref, "checks": checks,
            "limitations": ["Results cover the supplied cases. The assessor verifies the origin of the policy and CI observations."]}


def unique_keys(pairs):
    obj = dict(pairs)
    if len(obj) != len(pairs):
        raise ValueError("Duplicate JSON field.")
    return obj


def main():
    try:
        raw = sys.stdin.buffer.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError("Input exceeds one MiB.")
        result = review(json.loads(raw, object_pairs_hook=unique_keys))
    except (ValueError, RecursionError):
        print(json.dumps({"error": "invalid_input"}))
        return 2
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
