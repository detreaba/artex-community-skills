# Tier-2 delivery-shaping spec — buffering relay (draft 2026-11-21, owner session)

Status: draft for owner review. Defensive vocabulary throughout; lab-only.

## Problem
Tier-2 confirming probes must control *how* a request body reaches the backend,
not just its bytes. Raw client writes cannot shape: block size, inter-block
pacing, and header/body buffering separation. All three changed nothing on the
php2shell fixture geometry (16-config experiment, 2026-11-21: block 2048-8192,
gap 0.05-0.35s, with/without pre+tail spray — 16/16 identical 200s), which is
itself a usable negative control, and the reason the relay must exist as a
first-class harness piece rather than an ad-hoc script.

## Component
`vendor/strix/relay.py` (ARTEX-native, stdlib-only; provenance cited in
`vendor/strix/README.md`). One connection in, one backend connection out:

    relay.py --listen <port> --backend <host:port> --block <bytes> --gap <sec>

Contract:
- reads the client request fully (header + body per Content-Length);
- forwards headers immediately, body in `--block`-sized writes with `--gap`
  sleep after each block;
- streams the backend response back verbatim (no mutation, no re-chunking).

## Harness verbs (same shape as existing probe runners)
1. `observe`: run probe traffic through the relay with a named geometry
   `(block, gap)`; capture request-side timing and response into the evidence
   dir; record geometry in `capture.meta`.
2. `replay`: identical bytes, alternate geometry; evidence pair is diffable
   and the only delta is delivery timing.

## Integration
- `run.sh` gains `--relay <block>:<gap>` for slugs whose probes declare
  `delivery_sensitive: true` (php2shell: yes after Phase-1; others: no until
  a geometry witness says otherwise).
- Evidence schema: add `delivery: {block, gap, buffered: "full"}` to
  `capture.meta`; ledger rows for differentials record the geometry used on
  both halves (a pass is only valid when both halves share it).

## Deferred
- multi-request pipelining shapes (relay is one-shot per connection by design);
- TLS fronting (lab is loopback HTTP; real targets will need `--tls` passthrough);
- per-slug geometry presets once fpm-geometry witnesses land.
