---
name: sshd-posture
description: Observe one operator-named SSH endpoint's offered key-exchange, host-key, cipher and MAC algorithms plus its protocol version, then judge that posture offline against a forbidden/required policy as gap, pass or unknown. Tier 2 active check, split into a bounded live observer and an offline reader; loopback-verified; fails closed; the self-reported software version is advisory only.
---

# SSH posture check

For one SSH service the operator names, this answers: which key-exchange,
host-key, cipher and MAC algorithms does it **offer**, what protocol version does
it present, and does that meet the operator's policy?

It is a **Tier 2** skill, split so the repository's offline convention still
holds: `scripts/observe.py` makes the live observation, and `scripts/check.py`
judges a saved observation record with no network access.

## scripts/observe.py — the live part

Reads one JSON request on stdin and prints an observation record:

```json
{
  "target": {"host": "host.example", "port": 22, "address": "203.0.113.10"},
  "policy": {
    "forbidden": {"kex": ["diffie-hellman-group1-sha1"], "cipher": ["3des-cbc"], "mac": ["hmac-md5"], "hostkey": ["ssh-dss"]},
    "required": {"kex": ["curve25519-sha256"], "cipher": ["chacha20-poly1305@openssh.com"]}
  },
  "authorization_ref": "ticket or written authorization for observing this endpoint"
}
```

- **One endpoint per run.** `authorization_ref` is required. A list/range/wildcard
  host, a pinned `address` that is not an IP literal, or a non-object `policy`
  gives an `invalid_input` record and no connection is made. `port` defaults
  to 22.
- One TCP connection, 5s timeouts, no retries.
- It reads the server's identification line(s) (RFC 4253 §4.2; at most 64 lines /
  8 KiB), then sends one client identification line
  (`SSH-2.0-artex-sshd-posture-observer`) and one `SSH_MSG_KEXINIT` — the
  transport offer that elicits the server's KEXINIT even from a server that waits
  to read the client's first. It never sends `SSH_MSG_NEWKEYS`, completes key
  exchange, authenticates, opens a channel, or sends application data.
- It reads binary transport packets, skipping any number of `SSH_MSG_IGNORE` /
  `DEBUG` / `UNIMPLEMENTED` that precede key exchange (RFC 4253 §11 sets no count
  limit; bounded instead by a cumulative byte budget and the read timeout), until
  the server's `SSH_MSG_KEXINIT` (each `packet_length` capped at the RFC maximum
  of 35000 B), and parses the ten name-lists (kex, host-key, enc c2s/s2c, mac
  c2s/s2c, compression, languages).
- It then closes. It **never** authenticates, completes key exchange, opens a
  channel, or sends application data, and carries no exploit payload.

Standard library only, Python 3.9+. Build and verify against loopback fixtures
only; never point it at a host you are not authorized to observe.

## scripts/check.py — the offline reader

Reads a saved observation record and prints `gap` / `pass` / `unknown` per
category and overall:

```
python3 scripts/check.py < examples/pass.json
python3 scripts/check.py < examples/gap.json
python3 scripts/check.py < examples/unknown.json
```

Per category (`kex`, `hostkey`, `cipher`, `mac` — a category is judged only when
the policy names a `forbidden` or `required` set for it):

- any **offered** algorithm in `forbidden` → `gap`;
- a non-empty `required` set with no offered algorithm in it → `gap`;
- otherwise `pass`;
- a category the observation did not capture (no KEXINIT read) → `unknown`.

Overall: any `gap` → `gap`; all `pass` → `pass`; otherwise `unknown` (including a
policy with nothing to check). Malformed input fails closed to `unknown`.

**The identification string is advisory, never a verdict.** Both the software
name and the SSH protocol token (`SSH-2.0` / `SSH-1.99` / …) are self-reported and
can be forged, so the verdict rests only on the *offered* algorithms; the banner,
software and protocol are recorded as a note. An `SSH-1.x` / `1.99` token is
surfaced as an advisory note — confirming SSH-1 support would require an SSH-1
handshake, which this check does not perform.

## Limits

- Offered algorithms only — not what a specific client negotiates, nor
  `sshd_config` beyond what the offer reveals, nor authentication policy.
- Observed at one address and time.

## Compared with what exists

`tls-protocol-check` observes TLS version policy; this observes SSH algorithm
posture — both Tier 2 (bounded observe + offline check). `ssh-audit` covers
similar ground as an external tool; this packages a bounded, authorization-gated
observation plus an offline policy verdict in the repository's convention.
