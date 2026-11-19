"""Summarize saved Bandit findings and coverage without emitting source or filenames."""
import argparse
from collections import Counter, defaultdict
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import sys


MAX_BYTES = 32 * 1024 * 1024
RANKS = ("LOW", "MEDIUM", "HIGH", "UNDEFINED")
RULE = re.compile(r"B[0-9]{3}")


def unique_keys(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("Duplicate key.")
    return result


def read_json(stream, limit):
    raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("Oversized input.")
    return json.loads(raw, object_pairs_hook=unique_keys)


def digest(report):
    canonical = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def ref(value):
    return isinstance(value, str) and 0 < len(value.strip()) <= 1024


def counter_matches(metrics, observed):
    for category in ("SEVERITY", "CONFIDENCE"):
        for rank in RANKS:
            key = category + "." + rank
            if type(metrics.get(key)) is not int or metrics[key] != observed[key]:
                return False
    return True


def covered_metrics(metrics, observed):
    return (isinstance(metrics, dict) and type(metrics.get("loc")) is int and metrics["loc"] > 0
            and all(type(metrics.get(k)) is int and metrics[k] == 0 for k in ("nosec", "skipped_tests"))
            and counter_matches(metrics, observed))


def totals_match_files(metrics):
    rows = [row for path, row in metrics.items() if path != "_totals"]
    if not all(isinstance(row, dict) for row in rows):
        return False
    for key in ("loc", "nosec", "skipped_tests"):
        values = [row.get(key) for row in rows]
        if any(type(v) is not int or v < 0 for v in values) or sum(values) != metrics["_totals"].get(key):
            return False
    return True


def review(report, context):
    if not isinstance(report, dict) or not isinstance(context, dict):
        raise ValueError("Expected report and context objects.")
    results, errors, metrics = (report.get(k) for k in ("results", "errors", "metrics"))
    if not isinstance(results, list) or not isinstance(errors, list) or not isinstance(metrics, dict):
        raise ValueError("Missing native report fields.")
    timestamp = report.get("generated_at")
    if not isinstance(timestamp, str) or len(timestamp) > 40:
        raise ValueError("Missing native report timestamp.")
    generated = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    if generated.utcoffset() is None:
        raise ValueError("Expected an explicit time zone.")
    expected = context.get("expected_files", [])
    if (not isinstance(expected, list) or len(expected) > 4096
            or not all(ref(path) and path != "_totals" for path in expected) or len(set(expected)) != len(expected)):
        raise ValueError("Invalid expected files.")
    ci = context.get("ci", {})
    if not isinstance(ci, dict):
        raise ValueError("Invalid CI metadata.")
    signature = digest(report)
    bound = (ref(ci.get("run_ref")) and ci.get("report_digest") == signature and
             all(ref(context.get(k)) and ci.get(k) == context[k] for k in ("asset", "build", "policy")))
    full_policy = (bound and ci.get("policy_verified") is True and ci.get("unfiltered_output") is True
                   and ci.get("baseline_applied") is False and ci.get("run_completed") is True)
    positions = {path: i for i, path in enumerate(expected, 1)}
    per_file = defaultdict(Counter)
    totals = Counter()
    findings = []
    unrecognized = 0
    for issue in results:
        if not isinstance(issue, dict):
            unrecognized += 1
            continue
        path, rule, line = (issue.get(k) for k in ("filename", "test_id", "line_number"))
        severity, confidence = issue.get("issue_severity"), issue.get("issue_confidence")
        if (not ref(path) or not isinstance(rule, str) or not RULE.fullmatch(rule) or type(line) is not int
                or line < 1 or severity not in RANKS or confidence not in RANKS):
            unrecognized += 1
            continue
        counts = ("SEVERITY." + severity, "CONFIDENCE." + confidence)
        per_file[path].update(counts)
        totals.update(counts)
        if bound and path in positions:
            findings.append({"file_index": positions[path], "rule": rule, "line": line,
                             "severity": severity, "confidence": confidence})
    files = [{"file_index": i, "metrics_present": path in metrics,
              "metrics_complete": covered_metrics(metrics.get(path), per_file[path])}
             for path, i in positions.items()]
    global_ok = covered_metrics(metrics.get("_totals"), totals) and totals_match_files(metrics)
    complete = (full_policy and bool(files) and not errors and not unrecognized and global_ok
                and all(row["metrics_complete"] for row in files))
    status = "unknown"
    if findings:
        status = "gap"
    elif complete:
        status = "pass"
    return {"status": status, "coverage": "complete_for_expected_files" if complete else "incomplete",
            "report_digest": signature, "generated_at": generated.isoformat(), "bound_to_ci_run": bound, "full_policy_verified": full_policy,
            "aggregate_metrics_complete": global_ok, "processing_error_count": len(errors),
            "native_finding_count": len(results), "unrecognized_finding_count": unrecognized,
            "expected_files": files, "findings": findings}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    options = parser.add_mutually_exclusive_group()
    options.add_argument("--context", type=Path, help="read the CI context here and a native Bandit report on stdin")
    options.add_argument("--digest", action="store_true", help="print the canonical digest of a native report")
    args = parser.parse_args()
    try:
        data = read_json(sys.stdin.buffer, MAX_BYTES)
        if args.digest:
            if not isinstance(data, dict) or not {"results", "errors", "metrics"}.issubset(data):
                raise ValueError("Expected a native Bandit report.")
            print(digest(data))
            return 0
        if args.context is not None:
            with args.context.open("rb") as stream:
                result = review(data, read_json(stream, 2 * 1024 * 1024))
        elif isinstance(data, dict) and "report" in data:
            result = review(data["report"], data.get("context", {}))
        else:
            result = review(data, {})
        print(json.dumps(result))
    except (ValueError, OSError, RecursionError):
        print(json.dumps({"error": "invalid_input", "detail": "Check the saved Bandit report and review context."}))
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
