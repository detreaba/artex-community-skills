#!/usr/bin/env python3
"""Live observer for the sshd-posture check (Tier 2).

Reads one JSON request on stdin::

    {"target": {"host": ..., "port": 22, "address": ...},
     "policy": {"forbidden": {...}, "required": {...}},
     "authorization_ref": "..."}

It opens ONE TCP connection to one operator-named SSH endpoint, reads the
server's identification string and its ``SSH_MSG_KEXINIT``, and prints an
observation record that ``scripts/check.py`` reads offline. Standard library
only; Python 3.9+.

Scope and safety. One endpoint per run; ``authorization_ref`` is mandatory; a
list/range/wildcard host or a non-IP pinned ``address`` is ``invalid_input``.
The only bytes sent are one SSH identification line and one SSH_MSG_KEXINIT (the
transport offer that elicits the server's KEXINIT); it never sends NEWKEYS,
completes key exchange, authenticates, opens a channel, or sends application
data. Build and verify it against
loopback fixtures only; never point it at a host you are not authorized to
observe. It carries no exploit payload.
"""
import ipaddress
import json
import os
import socket
import struct
import sys
import time

TIMEOUT = 5
MAX_IDENT_LINE = 4096  # per-line cap on pre-banner/identification lines (memory bound)
MAX_PACKET = 35000  # RFC 4253 section 6.1 maximum uncompressed packet size
SSH_MSG_KEXINIT = 20
CLIENT_IDENT = b"SSH-2.0-artex-sshd-posture-observer\r\n"

# KEXINIT payload name-lists, in RFC 4253 section 7.1 order.
NAME_LISTS = ("kex_algorithms", "server_host_key_algorithms",
              "encryption_c2s", "encryption_s2c", "mac_c2s", "mac_s2c",
              "compression_c2s", "compression_s2c",
              "languages_c2s", "languages_s2c")


def _fail(reason):
    return {"skill": "sshd-posture", "observation_version": 1,
            "error": "invalid_input", "reason": reason}


def _is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


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
    port = target.get("port", 22)
    if isinstance(port, bool) or not isinstance(port, int) or not (1 <= port <= 65535):
        return None, "target.port must be an integer 1..65535"
    address = target.get("address")
    if address is not None and not (isinstance(address, str) and _is_ip(address)):
        return None, "target.address must be an IP literal (pin the resolved IP, not a hostname)"
    policy = req.get("policy")
    if policy is not None and not isinstance(policy, dict):
        return None, "policy must be an object"
    return req, None


def _read_identification(sock, deadline):
    """Read identification lines until an 'SSH-' line (RFC 4253 section 4.2),
    discarding any pre-banner lines. Bounded by the observation deadline and a
    per-line length cap (memory), not a line count or total size -- consistent
    with the KEXINIT read. Returns (banner_bytes, leftover_bytes), where
    ``leftover`` is whatever followed the identification line's newline (often
    the start of the binary KEXINIT), or (None, b"") on the deadline, EOF, or an
    over-long line.
    """
    buf = bytearray()
    while True:
        while b"\n" in buf:
            idx = buf.index(b"\n")
            raw = bytes(buf[:idx]).rstrip(b"\r")
            del buf[:idx + 1]
            if raw.startswith(b"SSH-"):
                return raw, bytes(buf)
            # a pre-banner line: discard it and keep scanning
        if len(buf) > MAX_IDENT_LINE:
            return None, b""  # a single line longer than the per-line cap
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None, b""
        try:
            sock.settimeout(remaining)
            chunk = sock.recv(256)
        except (socket.timeout, TimeoutError, OSError):
            return None, b""
        if not chunk:
            return None, b""
        buf.extend(chunk)


def _client_kexinit():
    """Build one client SSH_MSG_KEXINIT. Sending it elicits the server's KEXINIT
    even from a server that waits to read the client's first (RFC 4253 7.1). It
    advertises ordinary modern algorithms and is never followed by NEWKEYS, so no
    key exchange completes."""
    name_lists = (
        "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256",
        "ssh-ed25519,rsa-sha2-512,rsa-sha2-256",
        "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr",
        "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr",
        "hmac-sha2-256-etm@openssh.com,hmac-sha2-256",
        "hmac-sha2-256-etm@openssh.com,hmac-sha2-256",
        "none", "none", "", "",
    )
    payload = bytes([SSH_MSG_KEXINIT]) + os.urandom(16)
    for nl in name_lists:
        payload += struct.pack(">I", len(nl)) + nl.encode("ascii")
    payload += b"\x00" + struct.pack(">I", 0)  # first_kex_packet_follows, reserved
    base = 4 + 1 + len(payload)
    pad = 8 - (base % 8)
    if pad < 4:
        pad += 8
    return struct.pack(">I", 1 + len(payload) + pad) + bytes([pad]) + payload + b"\x00" * pad


def observe(req):
    target = req["target"]
    host = target["host"].strip()
    port = target.get("port", 22)
    policy = req.get("policy") if isinstance(req.get("policy"), dict) else {}

    record = {
        "skill": "sshd-posture",
        "observation_version": 1,
        "authorization_ref": req["authorization_ref"],
        "target": {"host": host, "port": port, "address": None},
        "policy": policy,
        "banner": None, "protocol": None, "software": None,
        "kexinit_read": False, "connections_made": 0, "notes": [],
    }

    addresses = []
    try:
        for info in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
            if info[4][0] not in addresses:
                addresses.append(info[4][0])
    except OSError as exc:
        return _fail("cannot resolve target.host: %s" % exc)
    dial = target.get("address") or (addresses[0] if addresses else None)
    if dial is None:
        return _fail("target.host resolved to no address")
    record["target"]["address"] = dial
    record["resolved_addresses"] = addresses

    sock = None
    try:
        sock = socket.create_connection((dial, port), timeout=TIMEOUT)
        sock.settimeout(TIMEOUT)
        record["connections_made"] = 1

        banner, leftover = _read_identification(sock, time.monotonic() + TIMEOUT)
        if banner is None:
            record["notes"].append("no SSH identification string within the observation window")
            return record
        record["banner"] = banner.decode("ascii", "replace")
        parts = record["banner"].split("-", 2)
        if len(parts) >= 3:
            record["protocol"] = parts[1]
            record["software"] = parts[2].split(" ", 1)[0]

        # Send our identification line and one KEXINIT: the transport-level offer
        # that elicits the server's KEXINIT even from a server that waits to read
        # the client's first. We never send NEWKEYS, complete key exchange,
        # authenticate, open a channel, or send any application data.
        sock.sendall(CLIENT_IDENT)
        sock.sendall(_client_kexinit())

        buf = bytearray(leftover)
        deadline = time.monotonic() + TIMEOUT

        def need(n):
            while len(buf) < n:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("observation window elapsed")
                sock.settimeout(remaining)
                chunk = sock.recv(4096)
                if not chunk:
                    raise EOFError("connection closed before %d bytes" % n)
                buf.extend(chunk)

        # SSH_MSG_IGNORE (2), SSH_MSG_UNIMPLEMENTED (3) and SSH_MSG_DEBUG (4) may
        # arrive before KEXINIT (RFC 4253 section 11) with no count limit; skip
        # any number of them -- bounded by a total-time observation window, not a
        # packet or byte count -- until KEXINIT (20), a disconnect (1), or an
        # unexpected message. A server that floods past the window reads unknown.
        try:
            skipped = 0
            while True:
                if time.monotonic() >= deadline:
                    record["notes"].append("KEXINIT not seen within the %ds observation window" % TIMEOUT)
                    return record
                need(4)
                (pkt_len,) = struct.unpack(">I", bytes(buf[:4]))
                if pkt_len < 2 or pkt_len > MAX_PACKET:
                    record["notes"].append("transport packet length out of bounds: %d" % pkt_len)
                    return record
                need(4 + pkt_len)
                body = bytes(buf[4:4 + pkt_len])
                del buf[:4 + pkt_len]
                pad_len = body[0]
                payload_len = pkt_len - pad_len - 1
                if payload_len < 1:
                    record["notes"].append("transport packet padding out of bounds: %d" % pad_len)
                    return record
                payload = body[1:1 + payload_len]
                msg = payload[0]
                if msg == SSH_MSG_KEXINIT:
                    off = 1 + 16  # message code + 16-byte cookie
                    for name in NAME_LISTS:
                        if off + 4 > len(payload):
                            raise ValueError("truncated name-list length")
                        (length,) = struct.unpack_from(">I", payload, off)
                        off += 4
                        if off + length > len(payload):
                            raise ValueError("truncated name-list body")
                        text = payload[off:off + length].decode("ascii", "replace")
                        off += length
                        # record tokens faithfully: no strip, no empty-drop, so an
                        # empty token (e.g. the comma-only body ",") or any other
                        # non-well-formed name is preserved for check.py -- the
                        # name-hygiene gate -- to flag. A length-0 name-list stays an
                        # empty list, a genuine "offers nothing" (distinct from ",").
                        record[name] = text.split(",") if text else []
                    record["kexinit_read"] = True
                    if skipped:
                        record["notes"].append("skipped %d pre-KEXINIT transport message(s)" % skipped)
                    return record
                if msg == 1:  # SSH_MSG_DISCONNECT
                    record["notes"].append("server disconnected before KEXINIT (msg 1)")
                    return record
                if msg in (2, 3, 4):  # IGNORE, UNIMPLEMENTED, DEBUG -- skip any number
                    skipped += 1
                    continue
                record["notes"].append("unexpected message before KEXINIT (msg %d)" % msg)
                return record
        except (EOFError, ValueError, struct.error, socket.timeout, TimeoutError) as exc:
            record["notes"].append("could not read/parse transport packets: %s" % exc)
            return record
    except (socket.timeout, TimeoutError):
        record["notes"].append("timeout")
        return record
    except OSError as exc:
        record["notes"].append("connection error: %s" % exc)
        return record
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


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
