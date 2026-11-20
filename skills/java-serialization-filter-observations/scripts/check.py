"""Summarize recorded filter presence for one owner-identified OpenJDK 21 JVM."""

import json
import re
import sys
from datetime import datetime


EVENT = "jdk.Deserialization"
ALIAS = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")
MAX_BYTES = 16 * 1024 * 1024


def alias(value):
    return value if isinstance(value, str) and ALIAS.fullmatch(value) else None


def fields(value, names):
    if not isinstance(value, dict) or value.keys() - names:
        raise ValueError("Unexpected input shape.")
    return value


def observation(event):
    if not isinstance(event, dict) or not isinstance(event.get("type"), str) or not event["type"]:
        return "unusable"
    if event["type"] != EVENT:
        return None
    values = event.get("values")
    if not isinstance(values, dict) or "filterStatus" not in values:
        return "unusable"
    configured = values.get("filterConfigured")
    status = values["filterStatus"]
    if configured is False and status is None:
        return "filter_absent"
    if configured is True and status in (None, "ALLOWED", "REJECTED", "UNDECIDED"):
        return "filter_present"
    return "unusable"


def jvm_identity(values):
    if not isinstance(values, dict):
        return None
    pid, start = values.get("pid"), values.get("jvmStartTime")
    if type(pid) is not int or pid <= 0 or not isinstance(start, str) or "T" not in start:
        return None
    try:
        parsed = datetime.fromisoformat(start.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (pid, start) if parsed.tzinfo is not None else None


def review(data):
    fields(data, {"inventory", "export_complete", "loss_events_included", "recording"})
    inventory = fields(data.get("inventory", {}), {"asset", "build", "instance", "ref", "jdk_major", "deployment_verified"})
    complete = data.get("export_complete")
    includes_loss = data.get("loss_events_included")
    if any(v is not None and type(v) is not bool for v in (complete, includes_loss)):
        raise ValueError("Invalid completeness flag.")
    recording = fields(data.get("recording", {}), {"events"})
    events = recording.get("events")
    if events is not None and not isinstance(events, list):
        raise ValueError("Expected an event array.")
    scope = {key: alias(inventory.get(key)) for key in ("asset", "build", "instance")}
    ref = alias(inventory.get("ref"))
    result = {
        "status": "unknown", "reason": "A verified JDK 21 recording for one serving JVM generation is required.",
        "scope": scope, "evidence_refs": {"recording": ref}, "observations": None,
        "data_loss_events": None, "export_coverage": "unknown",
    }
    major = inventory.get("jdk_major")
    if (not all(scope.values()) or not ref or inventory.get("deployment_verified") is not True
            or type(major) is not int or major != 21):
        return result
    if events is None:
        result["reason"] = "Supply the recording's event array."
        return result

    counts = {"filter_present": 0, "filter_absent": 0, "unusable": 0}
    loss_count = 0
    identity = None
    for event in events:
        kind = event.get("type") if isinstance(event, dict) else None
        if kind == "jdk.DataLoss":
            loss_count += 1
            continue
        if kind == "jdk.JVMInformation":
            current = jvm_identity(event.get("values"))
            if current is None or (identity is not None and current != identity):
                result["reason"] = "The JVM information records cannot establish one consistent process and start."
                return result
            identity = current
            continue
        key = observation(event)
        if key is not None:
            counts[key] += 1
    result["observations"] = counts
    result["data_loss_events"] = loss_count
    if complete is False or includes_loss is False or loss_count or counts["unusable"]:
        result["export_coverage"] = "partial"
    elif complete is True and includes_loss is True:
        result["export_coverage"] = "complete"

    if counts["filter_absent"]:
        result.update(status="filter_absent_on_recorded_check",
                      reason="At least one recorded check had no stream filter.")
    elif not counts["filter_present"]:
        result["reason"] = "No usable deserialization check was observed."
    elif result["export_coverage"] != "complete":
        result["reason"] = "Some checks had a filter, but the selected recording's event evidence is incomplete."
    else:
        result.update(status="filter_seen_on_recorded_checks",
                      reason="Every recorded deserialization check in this export had a stream filter.")
    if loss_count:
        result["reason"] += " The recording reports data loss."
    return result


def unique_keys(pairs):
    obj = dict(pairs)
    if len(obj) != len(pairs):
        raise ValueError("Duplicate JSON field.")
    return obj


def invalid_constant(value):
    raise ValueError("Invalid JSON literal.")


def main():
    try:
        raw = sys.stdin.buffer.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError("Export exceeds 16 MiB.")
        data = json.loads(raw, object_pairs_hook=unique_keys, parse_constant=invalid_constant)
        result = review(data)
    except (ValueError, RecursionError):
        print(json.dumps({"error": "invalid_input", "detail": "Check the JSON envelope, event array and 16 MiB limit."}))
        return 2
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
