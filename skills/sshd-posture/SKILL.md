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
- It sends its own client identification line (`SSH-2.0-artex-sshd-posture-observer`)
  **and one `SSH_MSG_KEXINIT` together, first**, immediately on connect (RFC 4253
  §4.2 does not fix an order, and §5.2 lets a client send additional data right
  after its identification string before receiving the server's — our KEXINIT is
  that additional data), then reads the server's identification line(s), discarding any
  pre-banner lines until the `SSH-` line — bounded by the observation window and a
  per-line length cap, not a line count or total size. Pipelining both first
  elicits the server's offer even from a peer that withholds its identification
  until it has read the client's identification **and** KEXINIT; reading first
  would deadlock there. It never sends `SSH_MSG_NEWKEYS`, completes key exchange,
  authenticates, opens a channel, or sends application data.
- It reads binary transport packets, skipping any number of `SSH_MSG_IGNORE` /
  `DEBUG` / `UNIMPLEMENTED` that precede key exchange (RFC 4253 §11 sets no count
  limit; bounded instead by a total-time observation window), until the server's
  `SSH_MSG_KEXINIT` (each `packet_length` capped at the RFC maximum of 35000 B),
  and parses the ten name-lists (kex, host-key, enc c2s/s2c, mac c2s/s2c,
  compression, languages). A server that floods past the window reads `unknown`.
- The binary packet stream begins at the single CR LF that terminates the
  identification string (RFC 4253 §4.2: the terminator is a single CR LF, and "All
  packets following the identification string SHALL use the binary packet
  protocol"). The observer frames packets from that point and does not
  resynchronise past stray bytes: an extra blank line *after* the `SSH-` line is
  not a binary packet, so it frames as an out-of-bounds `packet_length` and the
  observation reads `unknown` (a non-conformant server, fail-closed — not a false
  clean). This is distinct from a blank/other line *before* the `SSH-` line, which
  §4.2 permits and the observer skips.
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
- the name-lists are consulted only when `kexinit_read` is **JSON boolean `true`**
  — the one value `observe.py` writes once a KEXINIT is fully parsed (it also writes
  `false`, beside possibly-partial lists, on a truncated read). Any other value
  (`false`, absent, or a non-boolean such as `1` / `"true"` / `"false"`) means the
  offer was not confirmed captured, so every category reads `unknown` and the
  name-lists are not consulted. "Captured" throughout means a name-list read under a
  boolean-`true` flag;
- only a **JSON array** is read as a name-list. A direction that is not an array —
  absent, or a present non-array value such as a bare string `"3des-cbc"` or an
  on-the-wire comma string `"3des-cbc,aes256-ctr"` — is not a captured offer, so that
  direction reads `unknown` and its scalar is never tokenized (the same rule holds on
  the policy side: a non-array `forbidden`/`required` entry is unusable, not a name).
  This stays **unless** a captured (array) direction already shows a forbidden
  algorithm or is missing a required one, which still decides `gap`;
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

Matching is **exact token equality**, case-sensitive in full — never by prefix,
suffix or substring. RFC 4251 §6 makes the whole name case-sensitive ("Names are
case-sensitive"), including the `name@domain` form; the domain part is not folded
(§6 states no DNS case-insensitivity carve-out). So `hmac-sha2-256` and
`hmac-sha2-256-etm@openssh.com` are distinct names, and so are `x@openssh.com` and
`x@OpenSSH.COM`.

Overall: any `gap` → `gap`; all `pass` → `pass`; otherwise `unknown` (including a
policy with nothing to check). Malformed input fails closed to `unknown`.

The observation's `error` field is a record anomaly, not a mask: a present `error`
— truthy (as `observe.py` writes on failure, e.g. `invalid_input`) or a
non-standard falsy (`null`/`false`/`""`) — downgrades an otherwise-clean verdict to
`unknown` (fail-closed) but never masks a captured `gap`. A captured gap stands
because the `kexinit_read` gate judges name-lists only when the KEXINIT was fully
parsed, so a forbidden algorithm present under an error is a real detection.
(`observe.py`'s failure path returns a record with no `policy` and no name-lists, so
there is nothing to judge and it reads `unknown`; the observed `reason` is surfaced
as a note.)

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
