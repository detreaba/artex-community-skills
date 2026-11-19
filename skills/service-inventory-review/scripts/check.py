"""Compare a saved Nmap XML observation with an owner's approved listening ports."""
import argparse
import ipaddress
import json
import re
import sys
from pathlib import Path
from xml.etree.ElementTree import TreeBuilder
from xml.parsers import expat


XML_LIMIT = 2 * 1024 * 1024
ALIAS = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,95}")
PORT_NUMBER = re.compile(r"0|[1-9][0-9]{0,4}")
SCOPED = {"asset", "address", "deployment", "vantage", "ref"}
PROTOCOLS = {"tcp", "udp"}
PORT_STATES = {"open", "closed", "filtered", "unfiltered", "open|filtered", "closed|filtered"}


def fields(value, allowed):
    if not isinstance(value, dict) or value.keys() - allowed:
        raise ValueError("Unexpected fields.")
    return value


def unique_keys(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("Duplicate JSON key.")
    return result


def limited(stream, limit):
    raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("Input exceeds the size limit.")
    return raw


def alias(value):
    if value is None:
        return None
    if not isinstance(value, str) or not ALIAS.fullmatch(value):
        raise ValueError("Use short, opaque identifiers.")
    return value


def scope(record):
    result = {key: alias(record.get(key)) for key in ("asset", "deployment", "vantage")}
    addr = record.get("address")
    if addr is not None and (not isinstance(addr, str) or "%" in addr):
        raise ValueError("Use the recorded IPv4 or IPv6 address.")
    result["address"] = str(ipaddress.ip_address(addr)) if addr is not None else None
    return result


def number(raw):
    if not isinstance(raw, str) or not PORT_NUMBER.fullmatch(raw) or int(raw) > 65535:
        raise ValueError("Invalid port.")
    return int(raw)


def policy_ports(values):
    if not isinstance(values, list) or len(values) > 256:
        raise ValueError("Port policies accept up to 256 entries per list.")
    result = set()
    for value in values:
        if not isinstance(value, str):
            raise ValueError("Use protocol/port identifiers.")
        protocol, separator, port = value.partition("/")
        if protocol not in PROTOCOLS or not separator:
            raise ValueError("Use tcp or udp.")
        result.add((protocol, number(port)))
    return result


def xml_tree(raw):
    builder = TreeBuilder()
    parser = expat.ParserCreate()
    depth = 0
    count = 0

    def start(tag, attrs):
        nonlocal depth, count
        depth += 1
        count += 1
        if depth > 64 or count > 65536:
            raise ValueError("XML structure exceeds the supported limits.")
        builder.start(tag, attrs)

    def end(tag):
        nonlocal depth
        builder.end(tag)
        depth -= 1

    # Nmap itself emits the bare marker. A subset or external identifier is a DTD.
    def doctype(name, system, public, subset):
        if (name, system, public, subset) != ("nmaprun", None, None, 0):
            raise ValueError("External or internal document types are unsupported.")

    def reject(*args):
        raise ValueError("XML entities are unsupported.")

    parser.StartDoctypeDeclHandler = doctype
    parser.EntityDeclHandler = reject
    parser.ExternalEntityRefHandler = reject
    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.Parse(raw, True)
    return builder.close()


def addresses(host):
    found = set()
    for entry in host.findall("address"):
        if entry.get("addrtype", "ipv4") in {"ipv4", "ipv6"}:
            value = ipaddress.ip_address(entry.get("addr", ""))
            if entry.get("addrtype", "ipv4") != f"ipv{value.version}":
                raise ValueError("Invalid host address family.")
            found.add(str(value))
    return found


def port_records(host):
    observations = {}
    unmapped = False
    budget = 2 * 65536

    def add(key, state):
        if state not in PORT_STATES:
            state = "unknown"
        prior = observations.setdefault(key, state)
        if prior != state:
            observations[key] = "conflicting"

    for port in host.findall("ports/port"):
        proto = port.get("protocol")
        if proto not in PROTOCOLS | {"sctp", "ip"}:
            raise ValueError("Unknown port protocol.")
        if proto in PROTOCOLS:
            states = port.findall("state")
            state = states[0].get("state") if len(states) == 1 else "unknown"
            add((proto, number(port.get("portid"))), state or "unknown")
    for group in host.findall("ports/extraports"):
        state = group.get("state")
        total = int(group.get("count", "-1"))
        if not 0 <= total <= 2 * 65536:
            raise ValueError("Invalid aggregate port count.")
        mapped = 0
        for reason in group.findall("extrareasons"):
            proto = reason.get("proto")
            ports = reason.get("ports")
            if proto in {"sctp", "ip"}:
                count = int(reason.get("count", "-1"))
                if not 0 <= count <= total:
                    raise ValueError("Invalid aggregate port count.")
                mapped += count
                continue
            if proto not in PROTOCOLS or not ports:
                continue
            count = 0
            for item in ports.split(","):
                lo, dash, hi = item.partition("-")
                first = number(lo)
                last = number(hi) if dash else first
                width = last - first + 1
                if width < 1 or width > budget:
                    raise ValueError("Invalid or excessive grouped port ranges.")
                budget -= width
                count += width
                for port in range(first, last + 1):
                    if (proto, port) in observations:
                        raise ValueError("Grouped port identities overlap.")
                    add((proto, port), state or "unknown")
            if count != int(reason.get("count", "-1")):
                raise ValueError("Grouped port counts disagree.")
            mapped += count
        if mapped > total:
            raise ValueError("Grouped port counts disagree.")
        if state != "closed" and mapped < total:
            unmapped = True
    return observations, unmapped


def review(data, separate_xml=None):
    fields(data, {"policy", "report"})
    policy = fields(data.get("policy", {}), SCOPED | {"required", "allowed_open"})
    report = fields(data.get("report", {}), SCOPED | {"xml"})
    context = scope(policy)
    result = {**context, "policy_ref": alias(policy.get("ref")), "report_ref": alias(report.get("ref")),
              "finished_epoch": None, "status": "unknown", "coverage": "unknown", "checks": []}

    def insufficient(reason):
        return {**result, "reason": reason}

    if not all(context.values()) or not result["policy_ref"] or not result["report_ref"] or scope(report) != context:
        return insufficient("The policy and report need matching asset, deployment, address and vantage, with references.")
    if "required" not in policy or "allowed_open" not in policy:
        return insufficient("Supply the required observation list and an explicit list of approved listening ports.")
    required, allowed = policy_ports(policy["required"]), policy_ports(policy["allowed_open"])
    if not required:
        return insufficient("The baseline requires at least one observed endpoint.")
    if separate_xml is not None and "xml" in report:
        raise ValueError("Supply only one source of XML.")
    raw = separate_xml
    if "xml" in report:
        if not isinstance(report["xml"], str):
            raise ValueError("Supply XML text.")
        raw = report["xml"].encode("utf-8")
    if not raw:
        return insufficient("Supply the saved XML report.")
    if len(raw) > XML_LIMIT:
        raise ValueError("The XML report exceeds two MiB.")
    root = xml_tree(raw)
    if root.tag != "nmaprun" or root.get("scanner") != "nmap" or not re.fullmatch(r"1\.[0-9]+", root.get("xmloutputversion", "")):
        return insufficient("The artifact must be an Nmap XML 1.x report.")
    finished = root.findall("runstats/finished")
    if len(finished) != 1 or finished[0].get("exit") != "success" or finished[0].get("errormsg"):
        return insufficient("The saved job has no unambiguous successful completion.")
    timestamp = finished[0].get("time", "")
    if not re.fullmatch(r"[0-9]{1,12}", timestamp):
        return insufficient("The saved job has no valid completion time.")
    result["finished_epoch"] = int(timestamp)
    start = root.get("start")
    if start is not None and (not re.fullmatch(r"[0-9]{1,12}", start) or int(start) > int(timestamp)):
        return insufficient("The start and finish times disagree.")
    totals = root.findall("runstats/hosts")
    if len(totals) != 1:
        return insufficient("The terminal host summary is missing or ambiguous.")
    values = [totals[0].get(k, "") for k in ("up", "down", "total")]
    if not all(re.fullmatch(r"[0-9]{1,10}", v) for v in values):
        return insufficient("The terminal host counts are incomplete.")
    up, down, total = map(int, values)
    if up == 0 or up + down != total:
        return insufficient("The terminal host counts do not establish a live host in this snapshot.")
    hosts = [(host, addresses(host)) for host in root.findall("host")]
    matches = [(host, ips) for host, ips in hosts if context["address"] in ips]
    if len(matches) != 1 or len(matches[0][1]) != 1:
        return insufficient("The report must contain one matching host record for the policy address.")
    host = matches[0][0]
    statuses = host.findall("status")
    if len(statuses) != 1 or statuses[0].get("state") != "up" or host.get("timedout") not in (None, "false"):
        return insufficient("The matching host has no complete up-state observation.")
    observations, unmapped = port_records(host)
    # Record positive exceptions beyond the required sample. Inconclusive rows
    # outside that sample still prevent a complete result when opening is unapproved.
    extra_open = {key for key, state in observations.items() if key not in allowed and state == "open"}
    reviewed_or_allowed = required | allowed
    uncertain_extra = any(key not in reviewed_or_allowed and state not in {"open", "closed"}
                          for key, state in observations.items())
    gap = False
    partial = unmapped or uncertain_extra
    for key in sorted(required | extra_open):
        state = observations.get(key, "unobserved")
        if state == "open" and key not in allowed:
            status = "gap"
            gap = True
        elif state in {"open", "closed"}:
            status = "pass"
        else:
            status = "unknown"
            partial = True
        result["checks"].append({"endpoint": f"{key[0]}/{key[1]}", "open_approved": key in allowed,
                                 "observed_state": state, "status": status})
    result.update(status="gap" if gap else "unknown" if partial else "pass",
                  coverage="partial" if partial else "complete_for_review",
                  unresolved_aggregate=unmapped, unresolved_extra_observation=uncertain_extra)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--xml-file", type=Path, help="read XML from an existing local file")
    args = parser.parse_args()
    try:
        raw = limited(sys.stdin.buffer, 4 * 1024 * 1024)
        data = json.loads(raw, object_pairs_hook=unique_keys)
        report = None
        if args.xml_file:
            if not args.xml_file.is_file():
                raise ValueError("Supply a regular file.")
            with args.xml_file.open("rb") as stream:
                report = limited(stream, XML_LIMIT)
        result = review(data, report)
    except (expat.ExpatError, OSError, ValueError, RecursionError):
        print(json.dumps({"error": "invalid_input", "detail": "Check the policy, file size and saved XML."}))
        return 2
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
