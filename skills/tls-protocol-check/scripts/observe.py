#!/usr/bin/env python3
"""Live observer for the TLS protocol-policy check (Tier 2).

Reads one JSON request on stdin::

    {"target": {"host": ..., "port": ..., "sni": ..., "address": ...},
     "policy": {"must_refuse": ["1.0", "1.1"], "must_accept": ["1.2", "1.3"]},
     "authorization_ref": "..."}

It makes at most five sequential, plain TLS handshakes to ONE operator-named
endpoint, sends no application data, and prints an observation record that
``scripts/check.py`` reads offline. Standard library only; Python 3.9+.

Scope and safety. One endpoint the operator names per run; ``authorization_ref``
is mandatory; a list, range or wildcard host is ``invalid_input``. Build and
verify it against loopback fixtures only and never point it at a host you are
not authorized to observe. It carries no exploit payload: it offers one TLS
version per connection and records how the service replied.
"""
import hashlib
import json
import socket
import ssl
import sys

VMAP = {
    "1.0": ssl.TLSVersion.TLSv1,
    "1.1": ssl.TLSVersion.TLSv1_1,
    "1.2": ssl.TLSVersion.TLSv1_2,
    "1.3": ssl.TLSVersion.TLSv1_3,
}
ORDER = ("1.0", "1.1", "1.2", "1.3")
MAX_CONNECTIONS = 5
TIMEOUT = 5

# Map an exact OpenSSL reason string to an observation class. Only
# TLSV1_ALERT_PROTOCOL_VERSION is treated as a protocol refusal downstream.
REASON_CLASS = {
    "TLSV1_ALERT_PROTOCOL_VERSION": "version_refused",
    "SSLV3_ALERT_HANDSHAKE_FAILURE": "handshake_failure",
    "UNEXPECTED_EOF_WHILE_READING": "closed",
    "WRONG_VERSION_NUMBER": "not_tls",
    "NO_CIPHERS_AVAILABLE": "client_cannot_offer",
}


def _fail(reason):
    return {"skill": "tls-protocol-check", "observation_version": 1,
            "error": "invalid_input", "reason": reason}


def _validate(req):
    if not isinstance(req, dict):
        return None, "request is not a JSON object"
    auth = req.get("authorization_ref")
    if not isinstance(auth, str) or not auth.strip():
        return None, "authorization_ref is required"
    target = req.get("target")
    if not isinstance(target, dict):
        return None, "target is required"
    host = target.get("host")
    if not isinstance(host, str) or not host.strip():
        return None, "target.host is required"
    if any(ch in host for ch in (",", "*", "/", " ")):
        return None, "target.host must be one host, not a list, range or wildcard"
    port = target.get("port")
    if isinstance(port, bool) or not isinstance(port, int) or not (1 <= port <= 65535):
        return None, "target.port must be an integer 1..65535"
    policy = req.get("policy") or {}
    must_refuse = policy.get("must_refuse") or []
    must_accept = policy.get("must_accept") or []
    if not isinstance(must_refuse, list) or not isinstance(must_accept, list):
        return None, "policy.must_refuse and policy.must_accept must be lists"
    for v in list(must_refuse) + list(must_accept):
        if str(v) not in VMAP:
            return None, "unknown TLS version %r; use 1.0 1.1 1.2 1.3" % (v,)
    if not must_refuse and not must_accept:
        return None, "policy lists at least one version to refuse or accept"
    return req, None


def _classify(exc):
    reason = getattr(exc, "reason", None)
    if not reason:
        text = str(exc).upper()
        for key in REASON_CLASS:
            if key in text:
                reason = key
                break
    if reason and reason in REASON_CLASS:
        return REASON_CLASS[reason], reason
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "timeout", reason or "timeout"
    if isinstance(exc, ConnectionResetError):
        return "closed", reason or "connection_reset"
    return "unclassified", reason or str(exc)


def _context(low, high):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = low
    ctx.maximum_version = high
    # Let the client actually offer the legacy versions, so a refusal reflects
    # the server's policy and not our own security level. If the local OpenSSL
    # still cannot offer, the handshake raises NO_CIPHERS_AVAILABLE and the
    # attempt is recorded as client_cannot_offer.
    if low != ssl.TLSVersion.TLSv1_3:
        try:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            pass
    return ctx


def _handshake(address, port, sni, low, high, read_after=False):
    """Make exactly one connection; return (class, detail)."""
    detail = {"negotiated": None, "reason": None, "cert_sha256": None, "notes": []}
    ctx = _context(low, high)
    sock = None
    ssock = None
    try:
        sock = socket.create_connection((address, port), timeout=TIMEOUT)
        sock.settimeout(TIMEOUT)
        ssock = ctx.wrap_socket(sock, server_hostname=sni)
        detail["negotiated"] = ssock.version()
        der = ssock.getpeercert(binary_form=True)
        if der:
            detail["cert_sha256"] = hashlib.sha256(der).hexdigest()
        if read_after:
            # A server can still demand a client certificate right after a
            # TLS 1.3 handshake; read briefly for that alert, send nothing.
            try:
                ssock.settimeout(1)
                ssock.recv(1)
            except ssl.SSLError as exc:
                reason = getattr(exc, "reason", None) or str(exc)
                detail["notes"].append("post-handshake alert: %s" % reason)
            except (socket.timeout, TimeoutError):
                pass
            except OSError:
                pass
        return "negotiated", detail
    except ssl.SSLError as exc:
        klass, reason = _classify(exc)
        detail["reason"] = reason
        return klass, detail
    except (socket.timeout, TimeoutError):
        detail["reason"] = "timeout"
        return "timeout", detail
    except ConnectionResetError:
        detail["reason"] = "connection_reset"
        return "closed", detail
    except OSError as exc:
        klass, reason = _classify(exc)
        detail["reason"] = reason
        return klass, detail
    finally:
        try:
            if ssock is not None:
                ssock.close()
            elif sock is not None:
                sock.close()
        except OSError:
            pass


def observe(req):
    target = req["target"]
    host = target["host"].strip()
    port = target["port"]
    sni = target.get("sni") or host
    policy = req.get("policy") or {}
    wanted = set(str(v) for v in (policy.get("must_refuse") or []))
    wanted |= set(str(v) for v in (policy.get("must_accept") or []))
    versions = [v for v in ORDER if v in wanted]

    addresses = []
    try:
        for info in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
            addr = info[4][0]
            if addr not in addresses:
                addresses.append(addr)
    except OSError as exc:
        return _fail("cannot resolve target.host: %s" % exc)
    pinned = target.get("address")
    if pinned:
        address = pinned
    elif addresses:
        address = addresses[0]
    else:
        return _fail("target.host resolved to no address")

    record = {
        "skill": "tls-protocol-check",
        "observation_version": 1,
        "authorization_ref": req["authorization_ref"],
        "target": {"host": host, "port": port, "sni": sni, "address": address},
        "resolved_addresses": addresses,
        "policy": {"must_refuse": [str(v) for v in (policy.get("must_refuse") or [])],
                   "must_accept": [str(v) for v in (policy.get("must_accept") or [])]},
        "openssl_version": ssl.OPENSSL_VERSION,
        "attempts": [],
        "control": None,
        "connections_made": 0,
    }

    made = 0
    for v in versions:
        if made >= MAX_CONNECTIONS - 1:  # reserve one connection for the control
            record["attempts"].append({"version": v, "class": "skipped",
                                       "reason": "connection budget reached",
                                       "negotiated": None, "cert_sha256": None,
                                       "notes": []})
            continue
        tv = VMAP[v]
        klass, detail = _handshake(address, port, sni, tv, tv, read_after=(v == "1.3"))
        made += 1
        record["attempts"].append({"version": v, "class": klass,
                                   "reason": detail["reason"],
                                   "negotiated": detail["negotiated"],
                                   "cert_sha256": detail["cert_sha256"],
                                   "notes": detail["notes"]})

    if made < MAX_CONNECTIONS:
        klass, detail = _handshake(address, port, sni,
                                   ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_3)
        made += 1
        record["control"] = {"class": klass, "negotiated": detail["negotiated"],
                             "reason": detail["reason"]}

    record["connections_made"] = made
    return record


def main(argv=None):
    data = sys.stdin.read()
    try:
        req = json.loads(data)
    except json.JSONDecodeError as exc:
        print(json.dumps(_fail("invalid JSON: %s" % exc), indent=2, sort_keys=True))
        return 0
    valid, err = _validate(req)
    if err:
        print(json.dumps(_fail(err), indent=2, sort_keys=True))
        return 0
    print(json.dumps(observe(valid), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
