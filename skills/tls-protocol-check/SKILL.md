---
name: tls-protocol-check
description: Observe whether one operator-named TLS endpoint accepts or refuses each TLS version a policy lists (1.0 to 1.3), then judge the saved observation offline as gap, pass or unknown. Tier 2 active check, split into a bounded live observer and an offline reader; loopback-verified; fails closed.
---

# TLS protocol-policy check

For one service the operator names, this answers a single question: does it
accept or refuse each TLS version the operator's policy lists? It covers direct
TLS only — no STARTTLS and no proxies — versions 1.0 through 1.3.

It is a **Tier 2** skill, split so the repository's offline convention still
holds: `scripts/observe.py` makes the live observation, and `scripts/check.py`
judges a saved observation record with no network access at all.

## scripts/observe.py — the live part

Reads one JSON request on stdin and prints an observation record:

```json
{
  "target": {"host": "host.example", "port": 443, "sni": "host.example", "address": "203.0.113.10"},
  "policy": {"must_refuse": ["1.0", "1.1"], "must_accept": ["1.2", "1.3"]},
  "authorization_ref": "ticket or written authorization for observing this endpoint"
}
```

- **One endpoint per run.** `authorization_ref` is required. A list, range or
  wildcard host, a missing `authorization_ref`, or an unknown version gives an
  `invalid_input` record and no connection is made.
- It resolves the name once and records every address, then uses one address
  (the pinned `address` if given) for every attempt.
- For each listed version it sends one ClientHello offering **only** that
  version, with SNI, and classifies the reply. For TLS 1.3 the offer goes in the
  `supported_versions` extension. One control handshake offers the whole range.
- After a completed TLS 1.3 handshake it reads for one second — a server can
  still demand a client certificate there — and records any alert as a note.
- It sends **no application data**, makes **at most five** sequential
  connections with 5-second timeouts and no retries, and carries no exploit
  payload. Certificate verification is off (this judges protocol acceptance, not
  certificates); each presented certificate's SHA-256 is recorded.

Standard library only, Python 3.9+. Build and verify it against loopback
fixtures only; never point it at a host you are not authorized to observe.

### Observation classes

| Reply to a ClientHello offering only version V | Class |
| --- | --- |
| Handshake completes at V | `negotiated` |
| `protocol_version` alert (`TLSV1_ALERT_PROTOCOL_VERSION`) | `version_refused` |
| `handshake_failure` alert | `handshake_failure` (client-cert demand at 1.2, or no shared cipher) |
| Another alert (e.g. `unrecognized_name`, `access_denied`) | `other_alert` |
| Close without an alert, or a reset | `closed` |
| No reply before the timeout | `timeout` |
| A non-TLS reply | `not_tls` |
| The local OpenSSL cannot offer V | `client_cannot_offer` |
| Anything else | `unclassified` (raw reason kept) |

Only the exact `protocol_version` reason counts as a refusal. Every other
reason is recorded verbatim with the OpenSSL version.

## scripts/check.py — the offline reader

Reads a saved observation record on stdin and prints `gap` / `pass` / `unknown`
per policy version and overall. The examples are synthetic saved records:

```
python3 scripts/check.py < examples/gap.json
python3 scripts/check.py < examples/pass.json
python3 scripts/check.py < examples/unknown.json
```

Verdict rules:

- **must-refuse version:** `negotiated` → `gap`. `version_refused` → `pass`
  *only when some handshake in the same run completed*; otherwise `unknown`.
- **must-accept version:** `negotiated` → `pass`. `version_refused` (same
  condition) → `gap`; otherwise `unknown`.
- **overall:** any `gap` → `gap`; all `pass` → `pass`; otherwise `unknown`.

The completed-handshake condition is the fail-closed guard: without one
negotiated handshake in the run, a server that answers every ClientHello with a
reset or a close is indistinguishable from one that is down or filtered, so its
refusals read `unknown`, never `pass`.

## Limits

- A `pass` covers one attempt per version, at this address, SNI and time —
  "refused on this attempt". A pool of servers behind one address, other
  addresses behind the name, other ports and later changes are not covered.
- A server that refuses with a bare close or reset can only ever read `unknown`.

## Compared with what exists

The SSLyze reader (skills covering a saved SSLyze report) interprets an
administrator's offline report per cipher suite for TLS 1.0/1.1. This skill
makes the observation itself, one handshake per version, 1.0 to 1.3, against a
declared policy; it is coarser, with no per-suite enumeration, so its `pass`
rests on a protocol-version alert.
