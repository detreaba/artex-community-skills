"""Check the Kubernetes privileged-container control on one archived Linux Pod."""
import json
import re
import sys


GROUPS = ("containers", "initContainers", "ephemeralContainers")
IDENTITY = ("namespace", "name", "uid", "resourceVersion")
ALIAS = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,252}")
CONTAINER_NAME = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
MAX_BYTES = 1024 * 1024


def fields(value, allowed):
    if not isinstance(value, dict) or value.keys() - set(allowed):
        raise ValueError("Unexpected wrapper fields.")
    return value


def ident(value):
    if value is not None and (not isinstance(value, str) or not ALIAS.fullmatch(value)):
        raise ValueError("Use short opaque identifiers.")
    return value


def unique(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("Duplicate key.")
    return result


def inspect_containers(spec, complete):
    rows = []
    names = set()
    for group in GROUPS:
        items = spec.get(group)
        if items is None:
            if group == "containers" or group in spec:
                complete = False
            continue
        if not isinstance(items, list):
            raise ValueError("A container collection must be a list.")
        if group == "containers" and not items:
            complete = False
        for item in items:
            if not isinstance(item, dict):
                raise ValueError("Invalid container object.")
            name = item.get("name")
            if not isinstance(name, str) or not CONTAINER_NAME.fullmatch(name) or name in names:
                raise ValueError("Container names must be unique DNS labels.")
            names.add(name)
            context = item.get("securityContext")
            if context is not None and not isinstance(context, dict):
                raise ValueError("Invalid container security context.")
            flag = None if context is None else context.get("privileged")
            if flag is not None and type(flag) is not bool:
                raise ValueError("The privileged field must be a boolean or null.")
            rows.append({"list": group, "name": name, "recorded_privileged": flag})
    return rows, complete


def review(data):
    fields(data, ("scope", "evidence"))
    request = fields(data.get("scope", {}), ("cluster", *IDENTITY))
    scope = {key: ident(request.get(key)) for key in ("cluster", *IDENTITY)}
    evidence = fields(data.get("evidence", {}), ("cluster", "source", "ref", "privilege_fields_complete", "pod"))
    full = evidence.get("privilege_fields_complete", False)
    if type(full) is not bool:
        raise ValueError("Invalid completeness indicator.")
    ref = ident(evidence.get("ref"))
    pod = evidence.get("pod", {})
    if not isinstance(pod, dict):
        raise ValueError("Invalid saved API object.")
    result = {"scope": scope, "evidence_ref": None, "status": "unknown", "containers": [],
              "coverage_complete": False, "standard_compliance": "unknown",
              "reason": "A referenced, persisted v1 Pod matching the requested identity is required."}
    metadata = pod.get("metadata", {})
    if (not all(scope.values()) or evidence.get("cluster") != scope["cluster"] or not ref
            or evidence.get("source") not in ("api-server-get", "persisted-admission-response")
            or pod.get("apiVersion") != "v1" or pod.get("kind") != "Pod" or not isinstance(metadata, dict)
            or any(metadata.get(key) != scope[key] for key in IDENTITY)):
        return result
    result["evidence_ref"] = ref
    spec = pod.get("spec", {})
    if not isinstance(spec, dict):
        raise ValueError("Invalid Pod spec.")
    os_field = spec.get("os")
    if not isinstance(os_field, dict) or os_field.get("name") != "linux":
        result["reason"] = "This check requires a Pod that explicitly declares Linux."
        return result

    rows, covered = inspect_containers(spec, full)
    for row in rows:
        value = row["recorded_privileged"]
        row["effective_privileged"] = False if value is None and covered else value
    result.update(containers=rows, coverage_complete=covered)
    if any(row["effective_privileged"] is True for row in rows):
        result.update(status="gap", reason="At least one identified container explicitly requests privileged mode.")
    elif covered:
        result.update(status="pass", reason="The complete retained container list has only false or unset privileged flags.")
    else:
        result["reason"] = "Coverage of container lists or their privileged fields is incomplete."
    return result


def main():
    try:
        raw = sys.stdin.buffer.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError("Input too large.")
        output = review(json.loads(raw, object_pairs_hook=unique))
    except (ValueError, RecursionError):
        print(json.dumps({"error": "invalid_input"}))
        return 2
    print(json.dumps(output))
    return 0


if __name__ == "__main__":
    sys.exit(main())
