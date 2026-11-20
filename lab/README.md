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

## Honesty rules
- `lab_differential: not-run` until a real run exists; never mark pass on design alone.
- The container must run **the configuration the advisory describes** (FastCGI for
  desync CVEs, `http2 on` for NGINX2Shell, etc.). Stock-up with nothing enabled
  tests the harness, not the CVE. Extend compose.yml accordingly before probing.
- Missing or unresolvable image tag => card status `blocked — no image`, not a
  downgrade to banner-suspect.
- Java4Shell is x86-64 only (AVX-512); an ARM runner result is meaningless.
