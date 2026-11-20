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
- It reads the server's identification line(s) (RFC 4253 §4.2), discarding any
  pre-banner lines until the `SSH-` line — bounded by the observation window and
  a per-line length cap, not a line count or total size. It then sends one client
  identification line (`SSH-2.0-artex-sshd-posture-observer`) and one
  `SSH_MSG_KEXINIT` — the
  transport offer that elicits the server's KEXINIT even from a server that waits
  to read the client's first. It never sends `SSH_MSG_NEWKEYS`, completes key
  exchange, authenticates, opens a channel, or sends application data.
- It reads binary transport packets, skipping any number of `SSH_MSG_IGNORE` /
  `DEBUG` / `UNIMPLEMENTED` that precede key exchange (RFC 4253 §11 sets no count
  limit; bounded instead by a total-time observation window), until the server's
  `SSH_MSG_KEXINIT` (each `packet_length` capped at the RFC maximum of 35000 B),
  and parses the ten name-lists (kex, host-key, enc c2s/s2c, mac c2s/s2c,
  compression, languages). A server that floods past the window reads `unknown`.
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
the policy names a `forbidden` or `required` set for it). `cipher` covers both
`enc_c2s`/`enc_s2c` and `mac` both `mac_c2s`/`mac_s2c`, and SSH negotiates the two
directions independently, so:

- `forbidden`: a positive detection — an algorithm offered in **any captured
  direction** that matches → `gap` (one captured direction is enough; it does not
  need every direction);
- `required`: **each direction** must offer a required algorithm — a captured
  direction offering none of the required set is a `gap`, so a required algorithm
  present in only one direction is still a `gap` (fail-closed, not the union);
- otherwise `pass`;
- when **no KEXINIT was read** (`kexinit_read` false or absent) the offer was not
  captured, so every category reads `unknown` and the name-lists are not consulted;
- within a read KEXINIT, a direction whose name-list is **missing** → `unknown`,
  **unless** a captured direction already shows a forbidden algorithm or is missing
  a required one, which still decides `gap`;
- an **empty** captured name-list (length 0 on the wire) is a real empty offer,
  distinct from an omitted field: it offers nothing, so it fails a `required`
  check (`gap`) and passes a `forbidden`-only one, while an **omitted** direction
  reads `unknown`;
- a captured name-list, or a policy list, carrying an element that is not a
  **well-formed name** — a non-string; a token with whitespace, a control/
  non-ASCII character, a comma, or over 64 characters; or a malformed `name@domain`
  (not exactly one `@`, an empty local part, or a domain that is not a
  fully-qualified name) (RFC 4251 §6) — keeps its valid names (a forbidden name
  among them still decides `gap`) and is otherwise malformed → `unknown`, so a
  token like `"3des-cbc "` or `"3des-cbc@"` cannot slip a `forbidden` match by
  reading as a distinct algorithm. `observe.py` records tokens faithfully (no
  strip, no empty-drop), so the comma-only body `","` reaches `check.py` as empty
  tokens and reads `unknown`, distinct from a length-0 empty offer; a policy category or section that is present but
  **null** or not a list is unusable → `unknown`; one that is simply absent, or an
  **empty** `forbidden`/`required` list, is no constraint. A malformed or unknown
  policy bit never masks a definite `gap`. The one asymmetry: a partial `required`
  list cannot *prove* a miss (the unreadable element may be the offered name), so a
  required-miss against it reads `unknown`, not `gap`; a hit against a partial
  `forbidden` list is still a definite `gap`.

Matching is **exact token equality** and case-sensitive (RFC 4251 §6): a policy
name matches an offered name only when the whole tokens are identical, never by
prefix, suffix or substring. `hmac-sha2-256` and `hmac-sha2-256-etm@openssh.com`
are distinct names.

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
