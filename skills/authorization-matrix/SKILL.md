---
name: authorization-matrix
description: Review saved authorization tests against an owner's policy for the same deployment. Use for role, tenant and ownership decisions and for documenting unverified cases.
---

# Compare expected and observed access

Ask for one versioned policy and redacted CI evidence for a specific asset and build. Assign a stable number to each case. Record role, tenant relation, resource ownership, resource type and operation in both the expectation and observation. Include allowed cases and denied cases. A generic HTTP status is insufficient evidence of the application's authorization decision.

The administrator can run the bundled checker from this skill's extracted directory with Python 3.9 or later and paste its JSON result into ARTEX.

```sh
python3 scripts/check.py < examples/gap.json
```

Use the [gap](examples/gap.json), [pass](examples/pass.json) and [older-build](examples/unknown.json) fixtures as input templates. Replace their sample identifiers and decisions with the deployment's evidence. Use opaque references to the policy and saved test records, with at most 128 rows of each type. A completed test carries an actual decision of `allow` or `deny`. Record failed or skipped tests with run state `error` or `skipped`.

Interpret each result by its case ID. `gap` means a recorded decision differed from the expected decision. `pass` means it matched. `unknown` means evidence was missing, conflicting or incomparable. An `invalid_input` response requires correcting the input before reporting results.

In Chat, cite the asset, build, policy reference and observation references for each conclusion. Identify the tenant and operation from the supplied policy. If the operator supplies only raw records, request the checker output or label your comparison as a manual review. Keep untested role and resource combinations visible. A later release needs new observations for the same case.
