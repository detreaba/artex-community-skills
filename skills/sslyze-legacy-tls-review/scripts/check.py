"""Review recorded SSLyze TLS 1.0 and 1.1 results from standard input."""
from datetime import datetime
import hashlib
from ipaddress import ip_address
import json
import re
import sys
from uuid import UUID


PROTOCOLS = {"TLS_1_0": "tls_1_0_cipher_suites", "TLS_1_1": "tls_1_1_cipher_suites"}
VERSIONS = {"6.1.0", "6.2.0", "6.3.0", "6.3.1"}
MAX_BYTES = 32 * 1024 * 1024
LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.I | re.ASCII)


def unique_keys(pairs):
    record = dict(pairs)
    if len(record) != len(pairs):
        raise ValueError("Duplicate JSON key.")
    return record


def name(value):
    if not isinstance(value, str) or len(value) > 254 or "%" in value:
        return None
    try:
        return str(ip_address(value))
    except ValueError:
        labels = value.removesuffix(".").split(".")
        return value if all(LABEL.fullmatch(label) for label in labels) else None


def outcome(status, reason):
    return {"status": status, "reason": reason}


def protocol_result(protocol, attempt, probed_version):
    if not isinstance(attempt, dict) or attempt.get("status") != "COMPLETED":
        return outcome("unknown", "The protocol command did not complete.")
    result = attempt.get("result")
    if (not isinstance(result, dict) or result.get("tls_version_used") != protocol
            or attempt.get("error_reason", True) is not None or attempt.get("error_trace", True) is not None):
        return outcome("unknown", "The command is incomplete or its evidence conflicts.")
    accepted = result.get("accepted_cipher_suites")
    rejected = result.get("rejected_cipher_suites")
    if not isinstance(accepted, list) or not isinstance(rejected, list):
        return outcome("unknown", "The cipher observations are missing.")
    cipher_names = set()
    for entry in accepted + rejected:
        if not isinstance(entry, dict) or not isinstance(entry.get("cipher_suite"), dict):
            return outcome("unknown", "A cipher observation is incomplete.")
        cipher = entry["cipher_suite"].get("name")
        if not isinstance(cipher, str) or not cipher or cipher in cipher_names:
            return outcome("unknown", "A cipher observation is incomplete.")
        cipher_names.add(cipher)
    if result.get("is_tls_version_supported") is True and accepted:
        return outcome("gap", "SSLyze recorded support for at least one cipher suite on this protocol.")
    if result.get("is_tls_version_supported") is not False or accepted or not rejected or probed_version == protocol:
        return outcome("unknown", "The support flag, cipher evidence or connectivity result is inconclusive.")
    # SSLyze also records handshake timeouts as rejections. Only an explicit
    # protocol-version alert supports this negative finding.
    if all(isinstance(e.get("error_message"), str)
           and e["error_message"].strip().casefold() == "tls alert: protocol version" for e in rejected):
        return outcome("pass", "Every recorded suite received an explicit protocol-version alert.")
    return outcome("unknown", "Some rejections lack an explicit protocol-version alert.")


def endpoint(row, index):
    if not isinstance(row, dict):
        raise ValueError("Invalid endpoint row.")
    location = row.get("server_location")
    config = row.get("network_configuration")
    if not isinstance(location, dict) or not isinstance(config, dict):
        raise ValueError("Invalid endpoint scope.")
    identifier = row.get("uuid")
    try:
        identifier = str(UUID(identifier)) if isinstance(identifier, str) else None
    except ValueError:
        identifier = None
    candidate_ip = location.get("ip_address")
    try:
        address = str(ip_address(candidate_ip)) if isinstance(candidate_ip, str) and "%" not in candidate_ip else None
    except ValueError:
        address = None
    port = location.get("port")
    scope = {"row": index, "uuid": identifier, "hostname": name(location.get("hostname")), "ip": address,
             "port": port if type(port) is int and 1 <= port <= 65535 else None,
             "sni": name(config.get("tls_server_name_indication"))}
    probe = row.get("connectivity_result")
    attempts = row.get("scan_result")
    if (not all(scope.values()) or location.get("connection_type") != "DIRECT"
            or location.get("http_proxy_settings", True) is not None
            or config.get("tls_opportunistic_encryption", True) is not None
            or config.get("tls_client_auth_credentials", True) is not None):
        issue = "The evidence does not identify a direct TLS endpoint and its SNI under the reviewed connection settings."
    elif (row.get("connectivity_status") != "COMPLETED" or row.get("scan_status") != "COMPLETED"
          or row.get("connectivity_error_trace", True) is not None or not isinstance(probe, dict)
          or probe.get("highest_tls_version_supported") not in ("SSL_2_0", "SSL_3_0", *PROTOCOLS, "TLS_1_2", "TLS_1_3")
          or not isinstance(attempts, dict)):
        issue = "The endpoint scan or its connectivity check did not supply a completed result."
    else:
        issue = None
    if issue:
        scope["protocols"] = {p: outcome("unknown", issue) for p in PROTOCOLS}
    else:
        scope["protocols"] = {p: protocol_result(p, attempts.get(key), probe["highest_tls_version_supported"])
                              for p, key in PROTOCOLS.items()}
    return scope


def stamp(value):
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError("Missing scan timestamp.")
    instant = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if instant.utcoffset() is None:
        raise ValueError("Timestamp needs a time zone.")
    return instant


def review(raw):
    data = json.loads(raw, object_pairs_hook=unique_keys)
    if not isinstance(data, dict):
        raise ValueError("Expected a report object.")
    version = data.get("sslyze_version")
    result = {"report_sha256": hashlib.sha256(raw).hexdigest(), "status": "unknown", "coverage": "incomplete"}
    if not isinstance(version, str) or version not in VERSIONS:
        return {**result, "reason": "The report lacks a supported SSLyze version.", "endpoints": []}
    rows = data.get("server_scan_results")
    invalid = data.get("invalid_server_strings")
    if not isinstance(rows, list) or not isinstance(invalid, list) or len(rows) + len(invalid) > 512:
        raise ValueError("Missing or oversized endpoint list.")
    start, end = stamp(data.get("date_scans_started")), stamp(data.get("date_scans_completed"))
    if start > end:
        raise ValueError("Inconsistent scan timestamps.")
    endpoints = [endpoint(row, i) for i, row in enumerate(rows, 1)]
    statuses = {entry["status"] for row in endpoints for entry in row["protocols"].values()}
    if endpoints and not invalid and "unknown" not in statuses:
        result["coverage"] = "complete_for_reported_endpoints"
        result["status"] = "pass"
    if "gap" in statuses:
        result["status"] = "gap"
    return {**result, "sslyze_version": version, "started_at": start.isoformat(), "completed_at": end.isoformat(),
            "invalid_target_count": len(invalid), "endpoints": endpoints}


def main():
    try:
        raw = sys.stdin.buffer.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError("Oversized report.")
        print(json.dumps(review(raw)))
    except (ValueError, RecursionError):
        print(json.dumps({"error": "invalid_input", "detail": "Check the SSLyze JSON report, timestamps and size."}))
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
