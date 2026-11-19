"""Review the displayed severity of one result in an existing Greenbone XML report."""
import hashlib
import json
import re
import shlex
import sys
from pathlib import Path
from xml.etree import ElementTree as ET

XML_LIMIT = 8 * 1024 * 1024
UUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")
OID = re.compile(r"[0-9]+(?:\.[0-9]+)+")
ALIAS = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}")
SCORE = re.compile(r"(?:[0-9](?:\.[0-9])?|10(?:\.0)?|-[123](?:\.0)?)")
QOD_TYPES = set("exploit remote_vul remote_app package registry remote_active remote_banner "
                "executable_version remote_analysis remote_probe remote_banner_unreliable "
                "executable_version_unreliable general_note".split())
LEVELS = dict(zip("chmlgf", ("Critical", "High", "Medium", "Low", "Log", "False Positive")))


class Inconclusive(Exception):
    """A valid export cannot establish the requested observation."""


class ReportTree(ET.TreeBuilder):
    def __init__(self):
        super().__init__()
        self.depth = 0
        self.count = 0

    def doctype(self, name, pubid, system):
        raise ValueError("Document type declarations are unsupported.")

    def start(self, tag, attrs):
        self.depth += 1
        self.count += 1
        if self.depth > 64 or self.count > 100000:
            raise ValueError("XML structure exceeds limits.")
        return super().start(tag, attrs)

    def end(self, tag):
        self.depth -= 1
        return super().end(tag)


def one(parent, path):
    nodes = parent.findall(path) if parent is not None else []
    if len(nodes) > 1:
        raise Inconclusive("The report contains ambiguous repeated fields.")
    return nodes[0] if nodes else None


def value(parent, path):
    node = one(parent, path)
    if node is None:
        return None
    if len(node):
        raise Inconclusive("A scalar field contains nested evidence.")
    return (node.text or "").strip()


def attr(parent, path, key):
    node = one(parent, path)
    return node.get(key) if node is not None else None


def score(text):
    if text and SCORE.fullmatch(text):
        return float(text)
    return None


def percent(text):
    if text and re.fullmatch(r"[0-9]{1,3}", text) and int(text) <= 100:
        return int(text)
    return None


def selected_report(root, report_id):
    if root.tag == "get_reports_response":
        if root.get("status") != "200":
            raise Inconclusive("The saved GMP response was unsuccessful.")
        shells = root.findall("report")
    elif root.tag == "report":
        shells = [root]
    else:
        raise ValueError("Expected a GMP report.")
    matches = [s for s in shells if s.get("id", "").lower() == report_id]
    if len(matches) != 1:
        raise Inconclusive("The selected report UUID must occur once.")
    outer = matches[0]
    if outer.get("extension", "xml").lower() != "xml":
        raise Inconclusive("The selected report is not an XML export.")
    inner = one(outer, "report")
    report = outer if inner is None else inner
    if (report.get("id", "").lower() != report_id or
            any(n.get("type", "scan") != "scan" or n.find("delta") is not None
                for n in (outer, report)) or
            value(one(report, "gmp"), "version") != "22.7"):
        raise Inconclusive("The record must identify the same GMP 22.7 scan report throughout.")
    return outer, report


def projection(report):
    filters = one(report, "filters")
    if filters is None:
        return {}, False
    term = value(filters, "term")
    names = ("apply_overrides", "overrides", "min_qod", "levels")
    fields = {name: [] for name in names}
    for name in names:
        direct = value(filters, name)
        if direct is not None:
            fields[name].append(direct)
    keywords = one(filters, "keywords")
    for keyword in keywords.findall("keyword") if keywords is not None else ():
        name = value(keyword, "column")
        if name in fields:
            fields[name].append(value(keyword, "value") if value(keyword, "relation") == "=" else None)
    if term and len(term) > 65536:
        raise Inconclusive("The filter term exceeds the supported length.")
    try:
        words = shlex.split(term or "")
    except ValueError:
        raise Inconclusive("The recorded filter term is incomplete.")
    options = {}
    consistent = True
    for name, entries in fields.items():
        # Use native structured fields for decisions. Compare the saved term when present.
        raw = [word.split("=", 1)[1] for word in words if word.startswith(name + "=")]
        entries_set = set(entries + raw)
        item = entries[0] if entries and len(entries_set) == 1 else None
        if name == "levels":
            parsed = [LEVELS[c] for c in item] if item and all(c in LEVELS for c in item) else None
        elif name == "min_qod":
            parsed = percent(item)
        else:
            parsed = {"1": True, "0": False}.get(item)
        if entries_set and parsed is None and not (name in ("min_qod", "levels") and entries_set == {""}):
            consistent = False
        options[name] = parsed
    labels = [node.text for node in filters.findall("filter")]
    if labels:
        if any(label not in LEVELS.values() for label in labels):
            consistent = False
        if options["levels"] and set(labels) != set(options["levels"]):
            consistent = False
        options["levels"] = [label for label in labels if label in LEVELS.values()]
    options["term_sha256"] = hashlib.sha256(term.encode("utf-8")).hexdigest() if term else None
    return options, consistent


def matching_override(result, oid, original, displayed, host, outer, report):
    entries = one(result, "overrides")
    rows = entries.findall("override") if entries is not None else []
    if len(rows) != 1:
        return False
    row = rows[0]
    if (not UUID.fullmatch(row.get("id", "")) or attr(row, "nvt", "oid") != oid
            or value(row, "active") != "1" or value(row, "orphan") != "0"
            or score(value(row, "new_severity")) != displayed):
        return False
    target = attr(row, "result", "id")
    task = attr(row, "task", "id")
    hosts, port = value(row, "hosts"), value(row, "port")
    if None in (target, task, hosts, port):
        return False
    if target and target.lower() != result.get("id").lower():
        return False
    if hosts and host not in [item.strip() for item in hosts.split(",")]:
        return False
    if port and port != value(result, "port"):
        return False
    if task:
        tasks = {attr(node, "task", "id") for node in (result, report, outer)}
        if not UUID.fullmatch(task) or {t.lower() for t in tasks if t} != {task.lower()}:
            return False
    constraint = value(row, "severity")
    if constraint == "":
        return True
    threshold = score(constraint)
    if threshold is None:
        return False
    return original >= threshold if threshold > 0 else original == threshold


def classify(root, request, out):
    report_id = request["report_id"].lower()
    result_id = request["result_id"].lower()
    outer, report = selected_report(root, report_id)
    try:
        out["filters"], consistent = projection(report)
    except Inconclusive:
        consistent = False
    results = one(report, "results")
    rows = [] if results is None else [n for n in results.findall("result")
                                        if n.get("id", "").lower() == result_id]
    if len(rows) != 1:
        raise Inconclusive("The selected result UUID must occur once in the report's results.")
    row = rows[0]
    host = one(row, "host")
    nvt = one(row, "nvt")
    linked_report = one(row, "report")
    if (host is None or (host.text or "").strip() != request["host"]
            or nvt is None or nvt.get("oid") != request["nvt_oid"]
            or (linked_report is not None and linked_report.get("id", "").lower() != report_id)
            or row.find("delta") is not None):
        raise Inconclusive("The selected host, VT and report must identify the same scan result.")
    out["nvt_oid"] = request["nvt_oid"]
    qod = one(row, "qod")
    out["qod"] = percent(value(qod, "value"))
    qod_type = value(qod, "type")
    out["qod_type"] = qod_type if qod_type in QOD_TYPES else None
    original = out["original_severity"] = score(value(row, "original_severity"))
    displayed = out["displayed_severity"] = score(value(row, "severity"))
    if None in (original, displayed) or min(original, displayed) < -1:
        raise Inconclusive("The result needs both severity scores in the supported range.")
    out["score_change"] = "unchanged" if original == displayed else (
        "lowered" if displayed < original else "raised")
    filters = out["filters"]
    if (not consistent or filters.get("apply_overrides") is None or out["qod"] is None
            or out["qod"] < (filters.get("min_qod") or 0)):
        raise Inconclusive("The report needs consistent export filters and a recorded result QoD.")
    level = {-1: "False Positive", 0: "Log"}.get(displayed) or value(row, "threat")
    if filters.get("levels") and level and level not in filters["levels"]:
        raise Inconclusive("The result's displayed level is excluded by the recorded export filters.")
    if original == displayed:
        return "pass", "The two recorded scores are equal for this result."
    if not filters["apply_overrides"] or filters["overrides"] is False:
        raise Inconclusive("The export did not establish both override application and a matching record.")
    # gvmd can substitute the current VT base for a positive stored severity.
    if value(nvt, "type") != "nvt" or (original > 0 and score(value(nvt, "cvss_base")) != original):
        raise Inconclusive("The saved VT evidence cannot rule out dynamic severity as a cause.")
    if not matching_override(row, request["nvt_oid"], original, displayed, request["host"], outer, report):
        raise Inconclusive("A single active override with matching scope and replacement score is required.")
    return "gap", "Review the recorded override that changed this result's displayed severity."


def review(request, file_xml):
    selectors = {"report_id", "result_id", "host", "nvt_oid"}
    if not isinstance(request, dict) or request.keys() - (selectors | {"xml", "asset", "ref"}):
        raise ValueError("Invalid envelope.")
    for name, text in request.items():
        if not isinstance(text, str) or (name != "xml" and len(text) > 255):
            raise ValueError("Invalid envelope value.")
    for key in ("asset", "ref"):
        if key in request and not ALIAS.fullmatch(request[key]):
            raise ValueError("Invalid alias.")
    for key, pattern in (("result_id", UUID), ("report_id", UUID), ("nvt_oid", OID)):
        if key in request and not pattern.fullmatch(request[key]):
            raise ValueError("Invalid selector.")
    if "xml" in request:
        if file_xml is not None:
            raise ValueError("Conflicting XML sources.")
        file_xml = request["xml"].encode("utf-8")
    out = {"asset": request.get("asset"), "evidence_ref": request.get("ref"), "nvt_oid": None, "status": "unknown",
           "score_change": "unknown", "original_severity": None, "displayed_severity": None,
           "qod": None, "qod_type": None, "filters": {}, "remediation": "unknown"}
    try:
        if file_xml is None:
            raise Inconclusive("A saved XML report is required.")
        if len(file_xml) > XML_LIMIT:
            raise ValueError("XML exceeds limit.")
        root = ET.fromstring(file_xml, parser=ET.XMLParser(target=ReportTree()))
        if not all(request.get(k) for k in selectors | {"asset", "ref"}):
            raise Inconclusive("Supply the report, result, host, VT and redacted evidence aliases.")
        out["status"], out["reason"] = classify(root, request, out)
    except Inconclusive as why:
        out["reason"] = str(why)
    return out


def unique(pairs):
    obj = dict(pairs)
    if len(obj) != len(pairs):
        raise ValueError("Repeated input key.")
    return obj


def limited(stream, size):
    data = stream.read(size + 1)
    if len(data) > size:
        raise ValueError("Input exceeds limit.")
    return data


def main():
    try:
        request = json.loads(limited(sys.stdin.buffer, 2 * XML_LIMIT), object_pairs_hook=unique)
        xml = None
        if sys.argv[1:]:
            if len(sys.argv) != 3 or sys.argv[1] != "--xml-file" or not Path(sys.argv[2]).is_file():
                raise ValueError("Expected a regular XML file.")
            with Path(sys.argv[2]).open("rb") as stream:
                xml = limited(stream, XML_LIMIT)
        print(json.dumps(review(request, xml)))
    except (ValueError, OSError, LookupError, ET.ParseError, RecursionError):
        print(json.dumps({"error": "invalid_input", "detail": "Check the scope JSON and GMP report XML."}))
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
