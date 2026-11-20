#!/usr/bin/env python3
"""Buffering relay for observation-session geometry (ARTEX-native; see README.md).

Fronts one TCP connection: reads the client's full request (header + body per
Content-Length), then forwards to the backend in fixed-size blocks with a fixed
gap, so body delivery timing is controlled by the relay, not the client.
Response streams back verbatim. Usage: relay.py --listen 8099 --backend 127.0.0.1:8091
"""
import argparse, socket, select, sys


def pump(src, dst, limit=None):
    data = b""
    while limit is None or len(data) < limit:
        chunk = src.recv(65536)
        if not chunk:
            break
        data += chunk
        if limit is None and b"\r\n\r\n" in data:
            break
    return data


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", type=int, default=8099)
    ap.add_argument("--backend", default="127.0.0.1:8091")
    ap.add_argument("--block", type=int, default=4096)
    ap.add_argument("--gap", type=float, default=0.0)
    a = ap.parse_args()
    bh, bp = a.backend.rsplit(":", 1)
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", a.listen))
    ls.listen(8)
    import time
    while True:
        c, _ = ls.accept()
        try:
            head = b""
            while b"\r\n\r\n" not in head:
                ch = c.recv(4096)
                if not ch:
                    break
                head += ch
            clen = 0
            for line in head.split(b"\r\n"):
                if line.lower().startswith(b"content-length:"):
                    clen = int(line.split(b":", 1)[1])
            body = b""
            while len(body) < clen:
                ch = c.recv(65536)
                if not ch:
                    break
                body += ch
            bsock = socket.create_connection((bh, int(bp)), timeout=40)
            bsock.sendall(head)
            for i in range(0, len(body), a.block):
                bsock.sendall(body[i:i + a.block])
                if a.gap:
                    time.sleep(a.gap)
            resp = b""
            while True:
                r, _, _ = select.select([bsock], [], [], 40)
                if not r:
                    break
                ch = bsock.recv(65536)
                if not ch:
                    break
                resp += ch
            c.sendall(resp)
        except Exception as e:
            print("relay:", type(e).__name__, e, file=sys.stderr)
        finally:
            c.close()


if __name__ == "__main__":
    main()
