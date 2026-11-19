"""Apply an owner's triage threshold to a saved ZAP Traditional JSON report."""
import argparse
import ipaddress
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit


LIMIT = 4 * 1024 * 1024
ALIAS = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")
RISK = ("informational", "low", "medium", "high")
CONFIDENCE = ("false_positive", "low", "medium", "high", "user_confirmed")


def fields(value, allowed):
    if not isinstance(value, dict) or value.keys() - allowed:
        raise ValueError("Unexpected owner record fields.")
    return value


def alias(value):
    if value is not None and (not isinstance(value, str) or not ALIAS.fullmatch(value)):
        raise ValueError("Use opaque identifiers.")
    return value


def unique_keys(pairs):
    obj = dict(pairs)
    if len(obj) != len(pairs):
        raise ValueError("Duplicate JSON key.")
    return obj


def read_json(stream):
    raw = stream.read(LIMIT + 1)
    if len(raw) > LIMIT:
        raise ValueError("Input exceeds four MiB.")
    return json.loads(raw, object_pairs_hook=unique_keys)


def code(value):
    if type(value) not in (int, str) or not re.fullmatch(r"0|[1-9][0-9]{0,8}", str(value)):
        return None
    return int(value)


def hostname(value):
    if not isinstance(value, str) or not value or len(value) > 253:
        return None
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    try:
        return str(ipaddress.ip_address(value)) if "%" not in value else None
    except ValueError:
        return value.lower() if re.fullmatch(r"[A-Za-z0-9.-]+", value) else None


def origin(value, instance=False):
    if not isinstance(value, str) or not value or any(ord(char) < 33 for char in value):
        return None
    try:
        url = urlsplit(value)
        if url.scheme not in ("http", "https") or url.username is not None or url.password is not None:
            return None
        if not instance and (url.path not in ("", "/") or url.query or url.fragment):
            return None
        host = hostname(url.hostname)
        port = url.port if url.port is not None else (443 if url.scheme == "https" else 80)
        return (url.scheme, host, port) if host and port > 0 else None
    except ValueError:
        return None


def selected_site(sites, wanted):
    if not isinstance(sites, list) or len(sites) > 1024:
        return None
    matches = []
    for site in sites:
        if not isinstance(site, dict):
            return None
        name = origin(site.get("@name"))
        tls = site.get("@ssl")
        if type(tls) is not bool and (not isinstance(tls, str) or tls not in ("true", "false")):
            return None
        scheme = "https" if tls in ("true", True) else "http"
        identity = (scheme, hostname(site.get("@host")), code(site.get("@port")))
        if name is None or name != identity:
            return None
        if name == wanted:
            matches.append(site)
    return matches[0] if len(matches) == 1 else None


def alert_row(alert, site_origin, min_risk, min_confidence):
    if not isinstance(alert, dict):
        return None
    rule = code(alert.get("pluginid"))
    risk = code(alert.get("riskcode"))
    confidence = code(alert.get("confidence"))
    count = code(alert.get("count"))
    instances = alert.get("instances")
    if (rule is None or risk not in range(len(RISK)) or confidence not in range(len(CONFIDENCE))
            or not count or not isinstance(instances, list) or count != len(instances)):
        return None
    if any(not isinstance(row, dict) or origin(row.get("uri"), instance=True) != site_origin for row in instances):
        return None
    reference = alert.get("alertRef")
    if not isinstance(reference, str) or not re.fullmatch(str(rule) + r"(?:-[0-9]{1,9})?", reference):
        reference = None
    return {"rule_id": rule, "alert_ref": reference, "risk": RISK[risk], "confidence": CONFIDENCE[confidence],
            "reported_instances": count, "meets_threshold": risk >= min_risk and confidence >= min_confidence}


def review(data, document=None):
    fields(data, {"policy", "evidence"})
    policy = fields(data.get("policy", {}), {"asset", "build", "ref", "origin", "min_risk", "min_confidence"})
    evidence = fields(data.get("evidence", {}), {"asset", "build", "ref", "run_status", "export_scope", "document"})
    if "document" in evidence:
        if document is not None:
            raise ValueError("Supply one report.")
        document = evidence["document"]
    scope = {key: alias(policy.get(key)) for key in ("asset", "build")}
    result = {**scope, "policy_ref": alias(policy.get("ref")), "report_ref": alias(evidence.get("ref")),
              "status": "unknown", "export_coverage": "unknown", "site_exposure": "unknown", "groups": []}

    def unknown(reason):
        return {**result, "reason": reason}

    if not all(scope.values()) or not result["policy_ref"] or not result["report_ref"] or any(evidence.get(k) != v for k, v in scope.items()):
        return unknown("Supply matching asset and build records with policy and report references.")
    site_origin = origin(policy.get("origin"))
    risk, confidence = policy.get("min_risk"), policy.get("min_confidence")
    if not site_origin or risk not in RISK or confidence not in CONFIDENCE[1:]:
        return unknown("A valid site origin and explicit minimum risk and confidence levels are required.")
    result.update(min_risk=risk, min_confidence=confidence)
    if evidence.get("run_status") != "completed":
        return unknown("The owner has not recorded successful completion of the assessment run.")
    if (not isinstance(document, dict) or not isinstance(document.get("@version"), str) or not document["@version"].strip()
            or not isinstance(document.get("@generated"), str) or not document["@generated"].strip()
            or document.get("@programName", "ZAP") not in ("ZAP", "OWASP ZAP")):
        return unknown("The report lacks recognizable ZAP Traditional JSON metadata.")
    site = selected_site(document.get("site"), site_origin)
    if site is None:
        return unknown("The saved report must identify one unambiguous matching origin.")
    alerts = site.get("alerts")
    if not isinstance(alerts, list) or not alerts:
        return unknown("No alert groups establish the assessed content for this origin.")
    incomplete = 0
    min_risk, min_confidence = RISK.index(risk), CONFIDENCE.index(confidence)
    for alert in alerts:
        row = alert_row(alert, site_origin, min_risk, min_confidence)
        if row is None:
            incomplete += 1
        else:
            result["groups"].append(row)
    complete = evidence.get("export_scope") == "all_recorded_alerts" and incomplete == 0
    qualifying = sum(item["meets_threshold"] for item in result["groups"])
    result.update(export_coverage="all_recorded_alerts" if complete else "partial",
                  incomplete_groups=incomplete, qualifying_groups=qualifying)
    if qualifying:
        result.update(status="gap", reason="Recorded alert groups meet the owner's triage threshold.")
    elif complete:
        result.update(status="pass", reason="Every group in the owner's complete saved export falls below the triage threshold.")
    else:
        result["reason"] = "Partial export or incomplete alert groups leave the threshold decision open."
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report-file", type=Path, help="read a saved local ZAP Traditional JSON export")
    args = parser.parse_args()
    try:
        data = read_json(sys.stdin.buffer)
        document = None
        if args.report_file:
            if not args.report_file.is_file():
                raise ValueError("Supply a regular file.")
            with args.report_file.open("rb") as stream:
                document = read_json(stream)
            if not isinstance(document, dict):
                raise ValueError("Supply a report object.")
        result = review(data, document)
    except (OSError, ValueError, RecursionError):
        print(json.dumps({"error": "invalid_input", "detail": "Check the owner record and the saved JSON file."}))
        return 2
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
