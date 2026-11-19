"""Review a saved Gitea job container's mount evidence without accessing Docker or its host."""
from collections import Counter
import json
import re
import sys


MAX_BYTES = 1024 * 1024
MAX_ROWS = 1024
LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}")
PLACEHOLDERS = {"unknown", "redacted", "unavailable", "unverified", "missing", "none", "null",
                "unset", "unspecified", "<redacted>", "[redacted]", "***"}


def label(value):
    return isinstance(value, str) and LABEL.fullmatch(value) is not None and value.lower() not in PLACEHOLDERS


def path(value):
    if not isinstance(value, str) or not value.startswith("/") or len(value) > 4096 or not value.isprintable():
        return False
    if value == "/":
        return True
    return all(part not in ("", ".", "..") and part.lower() not in PLACEHOLDERS for part in value[1:].split("/"))


def below(child, parent):
    return child != parent and (parent == "/" or child.startswith(parent + "/"))


def record(value):
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError("expected object")
    return value


def bounded_rows(value):
    if not isinstance(value, list) or len(value) > MAX_ROWS:
        raise ValueError("expected bounded list")
    return value


def classify(mount, proof, policy, coverage, destinations, every_destination_known):
    kind = mount.get("Type")
    dest = mount.get("Destination")
    source = mount.get("Source")
    if kind not in ("bind", "volume", "tmpfs"):
        return "unknown", "unsupported_mount_type"
    if not proof or proof.get("Type") != kind or proof.get("Source") != source:
        return "unknown", "backing_unverified"
    if kind == "tmpfs":
        if source in (None, "") and proof.get("kind") == "private" and proof.get("tree_complete") is True:
            return "clear", None
        return "unknown", "backing_unverified"
    if not path(source):
        return "unknown", "backing_unverified"
    if proof.get("kind") == "file":
        identity = proof.get("object")
        if not label(identity):
            return "unknown", "object_unverified"
        if identity == policy["socket_object"]:
            return "gap", "same_object"
        return "clear", None
    if proof.get("kind") != "directory" or not path(proof.get("canonical")):
        return "unknown", "backing_unverified"
    root = proof["canonical"]
    if proof.get("tree_complete") is not True or root in policy["socket_paths"]:
        return "unknown", "tree_unverified"
    if any(below(protected, root) for protected in policy["socket_paths"]):
        if (coverage != "complete" or not every_destination_known
                or any(below(other, dest) for other in destinations)):
            return "unknown", "parent_view_unverified"
        return "gap", "parent_directory"
    if policy.get("aliases_complete") is not True:
        return "unknown", "socket_aliases_incomplete"
    return "clear", None


def review(data):
    if not isinstance(data, dict):
        raise ValueError("expected root object")
    job = record(data.get("job"))
    policy = record(data.get("policy"))
    capture = record(data.get("inspect"))
    backing = record(data.get("backing"))
    refs = {k: obj["ref"] for k, obj in (("job", job), ("policy", policy), ("inspect", capture))
            if label(obj.get("ref"))}

    def result(status, reason, coverage="unassessed", gaps=(), unresolved=()):
        return {"status": status, "reason": reason, "coverage": coverage,
                "gaps": list(gaps), "unresolved": list(unresolved), "refs": refs}

    bindings = (("id", "job"), ("runner", "runner"), ("container", "Id"), ("build", "build"), ("daemon", "daemon"))
    if not label(job.get("ref")) or not label(capture.get("ref")) or any(
            not label(job.get(a)) or not label(capture.get(b)) for a, b in bindings):
        return result("unknown", "job_identity_unverified")
    if any(job[a] != capture[b] for a, b in bindings):
        return result("unknown", "job_identity_mismatch")
    if capture.get("kind") != "container_inspect" or capture.get("subject") != "job" or capture.get("os") != "linux":
        return result("unknown", "job_inspect_required")
    aliases = policy.get("socket_paths")
    if (not label(policy.get("ref")) or not label(policy.get("socket_ref"))
            or not label(policy.get("socket_object")) or policy.get("daemon") != job["daemon"]
            or policy.get("inspect_ref") != capture["ref"] or not isinstance(aliases, list)
            or not 1 <= len(aliases) <= 64 or not all(path(p) and p != "/" for p in aliases)):
        return result("unknown", "socket_identity_unverified")
    refs["socket"] = policy["socket_ref"]
    if capture.get("Mounts") is None:
        return result("unknown", "mounts_unavailable")
    rows = bounded_rows(capture["Mounts"])
    total = capture.get("total")
    if total is not None and (type(total) is not int or total < len(rows)):
        return result("unknown", "contradictory_count")
    complete = capture.get("coverage") == "complete" and (total is None or total == len(rows))
    coverage = "complete" if complete else "partial"

    # Tie each independent observation to the native destination, type, source and capture.
    destinations = Counter(m["Destination"] for m in rows if isinstance(m, dict) and path(m.get("Destination")))
    every_destination_known = sum(destinations.values()) == len(rows)
    proofs = {}
    if (label(backing.get("ref")) and backing.get("inspect_ref") == capture["ref"]
            and backing.get("daemon") == job["daemon"]):
        refs["backing"] = backing["ref"]
        observations = backing.get("mounts")
        for proof in bounded_rows([] if observations is None else observations):
            dest = proof.get("Destination") if isinstance(proof, dict) else None
            if not path(dest):
                if complete:
                    return result("unknown", "contradictory_backing")
                continue
            if complete and every_destination_known and dest not in destinations:
                return result("unknown", "contradictory_backing")
            proofs[dest] = None if dest in proofs else proof

    gaps, unresolved = [], []
    for i, mount in enumerate(rows, 1):
        if not isinstance(mount, dict) or not path(mount.get("Destination")):
            unresolved.append({"row": i, "reason": "destination_unverified"})
            continue
        dest = mount["Destination"]
        if destinations[dest] != 1:
            unresolved.append({"row": i, "reason": "duplicate_destination"})
            continue
        state, reason = classify(mount, proofs.get(dest), policy, coverage, destinations, every_destination_known)
        if state == "gap":
            gaps.append({"row": i, "basis": reason})
        elif state == "unknown":
            unresolved.append({"row": i, "reason": reason})
    if gaps:
        return result("gap", "socket_mounted", coverage, gaps, unresolved)
    if unresolved:
        return result("unknown", "unresolved_mounts", coverage, unresolved=unresolved)
    if not complete:
        return result("unknown", "incomplete_mounts", coverage)
    return result("pass", "socket_excluded", coverage)


def unique_keys(pairs):
    obj = dict(pairs)
    if len(obj) != len(pairs):
        raise ValueError("duplicate JSON key")
    return obj


def invalid_constant(_):
    raise ValueError("invalid JSON number")


if __name__ == "__main__":
    try:
        raw = sys.stdin.buffer.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError("oversize input")
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_keys, parse_constant=invalid_constant)
        print(json.dumps(review(data)))
    except (ValueError, RecursionError):
        print(json.dumps({"status": "invalid_input"}))
        sys.exit(2)
