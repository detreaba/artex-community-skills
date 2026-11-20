# vendor/strix — pinned Strix module copies

Source: usestrix/strix @ `a1ccf777d80e812edf23fc8b82bdc17def6143ac` (Apache-2.0, LICENSE retained).
Copied verbatim 2026-11-20 per the interactivity findings in `todo_artex.md`; files are
unmodified. Purpose: reference for the observation-session geometry work — an intercepting
relay lets a checker control exactly how a request body reaches the backend (block size,
pacing, buffering), which raw client writes cannot.

- `tools/proxy/caido_api.py`, `tools/proxy/tools.py` — Caido proxy client (optional backend).
- `runtime/caido_bootstrap.py`, `runtime/caido_handle.py` — proxy instance bring-up.
- `runtime/deferred_session.py` — long-lived session state across steps.

ARTEX-native piece (no Caido dependency): `relay.py` in this directory — stdlib-only
buffering relay with `--block`/`--gap` delivery shaping; same observe/replay verbs, works
in the lab without extra services. Modified/derived behavior is cited here, not in the
upstream copies.
