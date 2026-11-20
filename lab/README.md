# artex-lab — differential fixtures for ARTEX check-skills

Contract for the check-team (Codex manager, Opus/Grok authors/reviewers).

## What this is
A local lab of disposable Docker container pairs (vulnerable vs patched, pinned
tags from anything2shell.com advisories). A probe run here is a **fixture test**,
not a target engagement: the containers exist only to answer the differential
question for one card and are destroyed on teardown.

## How to run a differential
    ./run.sh <slug> <probe-script>
The probe script receives `$1=variant` and `$2=base_url` and writes the raw
response to stdout. Runner captures both halves plus exit codes into
`<slug>/evidence/<UTC-timestamp>/` and tears the pair down.

A differential PASSES when the probe's match-logic verdict is VULNERABLE on the
vulnerable half and NOT-VULNERABLE on the patched half. Ledger evidence = the
captured directory path.

## Verdict convention (Tier 2 probes) — owner ruling 2026-11-20
- Payloads, PoC probe bytes and match logic are authored by the **owner session**
  (and by author-role PRs), NOT by the manager/runner roles.
- A probe is a **black box** to the runner and manager: they execute it and record
  its output; they do not need to open, describe, or interpret its source.
- Every probe ends stdout with exactly one line:
  `# VERDICT: vulnerable|not-vulnerable|inconclusive <one-line basis>`
- The runner attaches the capture dir; `differential` in the ledger is set only
  from the two captured VERDICT lines plus evidence paths. Pass = VULNERABLE on
  the vulnerable half, NOT-VULNERABLE on the patched half; anything else is
  `fail` with the capture attached.

## Host access notes
- Non-login agent sessions: bare `docker` may be denied; use `sg docker -c '<command>'` (e.g. `sg docker -c './run.sh <slug> <probe>'` wrapped around the whole command).
- Probes under `probes/` are opaque payload files for runner/manager roles: execute, capture, record `# VERDICT:` lines; do not read probe source.

## Honesty rules
- `lab_differential: not-run` until a real run exists; never mark pass on design alone.
- The container must run **the configuration the advisory describes** (FastCGI for
  desync CVEs, `http2 on` for NGINX2Shell, etc.). Stock-up with nothing enabled
  tests the harness, not the CVE. Extend compose.yml accordingly before probing.
- Missing or unresolvable image tag => card status `blocked — no image`, not a
  downgrade to banner-suspect.
- Java4Shell is x86-64 only (AVX-512); an ARM runner result is meaningless.
