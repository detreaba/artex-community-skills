"""Read the host-specific credentialed-check flag from a saved Nessus v2 report."""
import json
import re
import sys
from pathlib import Path
from xml.etree.ElementTree import TreeBuilder
from xml.parsers import expat


XML_LIMIT = 8 * 1024 * 1024
ALIAS = re.compile(r"[A-Za-z0-9][A-Za-z0-9_./:@-]{0,95}")
LABEL = re.compile(r"[ \t]*Credentialed[ \t]+checks[ \t]*:[ \t]*(.*)", re.I | re.ASCII)
ACCOUNT = r"""(?:'[^'\r\n]{1,128}'|"[^"\r\n]{1,128}"|[\w.@\\/-]{1,128})"""
DIRECT_YES = re.compile(r"yes(?:,?[ \t]+(?:as[ \t]+" + ACCOUNT +
                        r",?[ \t]+)?via[ \t]+(?:ssh|smb))?", re.I | re.ASCII)


def limited(stream, limit):
    data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Input exceeds size limit.")
    return data


def reject(*args):
    raise ValueError("Unsupported input.")


def unique_keys(pairs):
    obj = dict(pairs)
    if len(obj) != len(pairs):
        raise ValueError("Duplicate key.")
    return obj


def read_xml(data):
    if len(data) > XML_LIMIT:
        raise ValueError("XML exceeds size limit.")
    parser = expat.ParserCreate(namespace_separator="}")
    tree = TreeBuilder()
    depth = count = 0

    def start(name, attrs):
        nonlocal depth, count
        depth += 1
        count += 1
        if depth > 64 or count > 100000:
            raise ValueError("XML structure exceeds limits.")
        tree.start(name, attrs)

    def end(name):
        nonlocal depth
        tree.end(name)
        depth -= 1

    parser.StartDoctypeDeclHandler = reject
    parser.ExternalEntityRefHandler = reject
    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = tree.data
    parser.Parse(data, True)
    root = tree.close()
    if root.tag != "NessusClientData_v2":
        raise ValueError("Expected Nessus v2 XML.")
    return root


def classify(root, request):
    reports = [r for r in root.findall("Report") if r.get("name") == request["report_name"]]
    if len(reports) != 1:
        return "unknown", "The report name must identify exactly one report."
    hosts = [h for h in reports[0].findall("ReportHost") if h.get("name") == request["host_name"]]
    if len(hosts) != 1:
        return "unknown", "The host name must identify exactly one host in the selected report."
    starts = hosts[0].findall("HostProperties/tag[@name='HOST_START']")
    if len(starts) != 1 or len(starts[0]) or starts[0].text != request["host_start"]:
        return "unknown", "The host start time does not establish the requested run."
    items = hosts[0].findall("ReportItem[@pluginID='19506']")
    if len(items) != 1:
        return "unknown", "The selected host must have exactly one scan-information result."
    outputs = items[0].findall("plugin_output")
    if len(outputs) != 1 or len(outputs[0]) or not outputs[0].text:
        return "unknown", "The scan-information output is missing or ambiguous."
    if outputs[0].text.rstrip().endswith("***TRUNCATED***"):
        return "unknown", "The export marks the scan-information output as truncated."
    fields = []
    for line in outputs[0].text.split("\n"):
        match = LABEL.fullmatch(line)
        if match:
            fields.append(match.group(1).strip(" \t"))
    if len(fields) == 1:
        if fields[0].lower() == "no":
            return "reported_no", "Nessus recorded a negative credentialed-check flag for this host."
        if DIRECT_YES.fullmatch(fields[0]):
            plugin_ids = {item.get("pluginID") for item in hosts[0].findall("ReportItem")}
            blockers = sorted(plugin_ids.intersection({"21745", "110695"}))
            if blockers:
                return "unknown", ("Plugin 19506 reports credentialed checks=yes. OS patch assessment was "
                                   "unavailable according to " + ", ".join(blockers) + ".")
            return "reported_yes", "Nessus recorded an affirmative credentialed-check flag for this OS host."
    return "unknown", "A single recognized OS credentialed-check value is required."


def review(request, file_xml=None):
    allowed = {"asset", "run", "ref", "direct_os_scan_verified", "coverage_records_complete",
               "report_name", "host_name", "host_start", "xml"}
    if not isinstance(request, dict) or request.keys() - allowed:
        raise ValueError("Unexpected fields.")
    aliases = {k: request.get(k) for k in ("asset", "run", "ref")}
    if any(v is not None and (not isinstance(v, str) or not ALIAS.fullmatch(v)) for v in aliases.values()):
        raise ValueError("Use redacted aliases.")
    selectors = [request.get(k) for k in ("report_name", "host_name", "host_start")]
    if any(v is not None and (not isinstance(v, str) or len(v) > 512 or not v.isprintable())
           for v in selectors):
        raise ValueError("Invalid report selector.")
    verified = request.get("direct_os_scan_verified")
    complete = request.get("coverage_records_complete")
    if any(v is not None and type(v) is not bool for v in (verified, complete)):
        raise ValueError("Invalid verification flag.")
    xml = file_xml
    if "xml" in request:
        if file_xml is not None or not isinstance(request["xml"], str):
            raise ValueError("Supply one XML source.")
        xml = request["xml"].encode("utf-8")
    root = read_xml(xml) if xml is not None else None
    if root is None or not all(aliases.values()) or not all(selectors) or verified is not True:
        status, reason = "unknown", "A referenced report bound to the selected direct OS scan and host is required."
    elif complete is not True:
        status, reason = "unknown", "The export must retain the selected host's relevant scan-information and assessment records."
    else:
        status, reason = classify(root, request)
    return {"asset": aliases["asset"], "run": aliases["run"], "evidence_ref": aliases["ref"], "plugin_id": 19506,
            "status": status, "reason": reason}


def main():
    try:
        request = json.loads(limited(sys.stdin.buffer, 2 * XML_LIMIT), object_pairs_hook=unique_keys,
                             parse_constant=reject)
        file_xml = None
        args = sys.argv[1:]
        if args:
            if len(args) != 2 or args[0] != "--xml-file" or not Path(args[1]).is_file():
                raise ValueError("Supply a regular XML file.")
            with Path(args[1]).open("rb") as stream:
                file_xml = limited(stream, XML_LIMIT)
        result = review(request, file_xml)
    except (ValueError, LookupError, OSError, expat.ExpatError, RecursionError):
        print(json.dumps({"error": "invalid_input", "detail": "Check the evidence fields, file size and Nessus v2 XML."}))
        return 2
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
