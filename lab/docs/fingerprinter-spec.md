# Tier-0 component fingerprinter — spec (draft 2026-11-21, owner session)

Status: draft for owner review; vocabulary consistent with lab surfaces.

## Purpose
Answer, per endpoint, *which* component/shape family is present, cheaply and
non-invasively, so Tier-1 probes are selected rather than sprayed. Today the
ledger's five slugs each require a human to decide "does this probe apply";
the fingerprinter makes that a machine step and records the basis.

## Inputs
- base URL (+ authorized scope tag, same `authorization_ref` discipline as probes)
- optional: existing capture dirs to avoid re-observing

## Features collected (Tier-0 only — ordinary requests, no malformed input)
Per slug, from one GET / plus one harmless POST:
1. response header set + values (`server`, `x-powered-by`, `x-turbo-charged-by`,
   security headers) — LiteSpeed/apache/nginx/fpm-via-proxy discrimination;
2. status + body-shape hash of a 404 and of the index (component error pages);
3. cookie names/flags (session backend hints);
4. TLS/JA3-lite (cipher preference ordering) as corroborating signal only;
5. timing histogram (3 samples) for async-backend detection.

## Output schema (one JSON per endpoint, stored under `<slug>/fingerprints/`)
```
{ "fingerprint_version": 1, "authorization_ref": "...", "url": "...",
  "observed": { "headers": {...}, "shape_hashes": {...}, "cookies": [...],
                "tls_lite": "...", "timing_ms": [...] },
  "component_candidates": [ {"family": "php2shell", "confidence": "high|med|low",
                              "basis": ["header:server=litespeed", "cookie=PHPSESSID"]} ],
  "probe_plan": ["php2shell/probes/..."],
  "verdict_basis_note": "..." }
```
Determination rule: a family is "high" only on ≥2 independent features;
single-feature matches are "med" and *never* suppress other slugs' probes.
Ambiguity (e.g. CDN-masked headers) is recorded as `unknown` with the masking
evidence — same fail-closed philosophy as the sshd-posture skill:
**no confident clean or dirty without features to back it.**

## Integration
- `run.sh --fingerprint <url>` writes the JSON and prints the probe_plan;
- Tier-1 execution consumes `probe_plan` instead of the full slug matrix;
- fingerprint JSONs are evidence: sha256-pinned in `capture.meta` like captures.

## Non-goals
- no vulnerability claims at Tier-0 (fingerprint never says vulnerable/not-vulnerable);
- no active version enumeration beyond header disclosure (keeps footprint
  passive-shaped and quiet);
- no external services — loopback/lab or authorized target only.

## Open questions (owner)
- confidence thresholds for "med → probe anyway" policy;
- whether fingerprints join `ledger.tsv` as a column or stay per-slug files.
