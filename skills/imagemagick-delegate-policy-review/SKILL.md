---
name: imagemagick-delegate-policy-review
description: Review whether a saved effective ImageMagick policy denies delegate execution on one identified worker and build.
---

# Review ImageMagick delegate policy

Use this skill when an image worker is required to deny all external delegates. The reader evaluates the execute right in the delegate domain. Its finding describes the saved policy. Availability or use of a particular delegate requires separate evidence. [ImageMagick security policy](https://imagemagick.org/security-policy/) · [Delegate authorization in MagickCore](https://github.com/ImageMagick/ImageMagick/blob/dcec873ede2912a1b045a50fd54cd138ee5f3fa4/MagickCore/delegate.c#L1811-L1817)

Run the offline reader with Python 3.9 or later. The sample records a wildcard denial followed by a named execute permission.

```sh
python3 scripts/check.py < examples/gap.json
```

## Prepare the worker record

- Set `worker.id` and `worker.build` to opaque aliases for the intended worker and the binary or linked library it actually loaded. In `export`, record the observed `worker` and `build` aliases independently. Use `ref` for the redacted export and `version_ref` for the saved evidence identifying the running build and its policy implementation. A package inventory or a separate command-line binary cannot establish that identity.
- Supply `product` as `imagemagick` and the full upstream `version` including the release suffix. Set `origin` to `upstream` for a verified upstream implementation. Use `upstream_equivalent` for a downstream build only when the referenced vendor or source comparison confirms the same delegate lookup, policy matching and precedence. An unknown or modified implementation needs its own review.
- Set `kind` to `effective` for a reconstruction or export of the policy actually loaded on this worker. Use `listing` for a standalone policy listing or `policy_file` for a file fragment. In `coverage`, set each field to true only when the evidence establishes it. `loaded` means the policy loaded successfully. `order` means rule order at evaluation time. `files_and_includes` covers active configuration files, overlays and their expanded includes. `builtins` covers compiled policies, including zero-configuration builds. `stealth` covers entries omitted from display. `runtime` covers changes made by the application through the capture time. For each source class establish inclusion or verified absence. An ordinary listing filters entries and cannot substantiate all six fields. [Policy listing](https://github.com/ImageMagick/ImageMagick/blob/dcec873ede2912a1b045a50fd54cd138ee5f3fa4/MagickCore/policy.c#L432-L454) · [Application-supplied policy](https://github.com/ImageMagick/ImageMagick/blob/dcec873ede2912a1b045a50fd54cd138ee5f3fa4/MagickCore/policy.c#L1563-L1608)
- In `export.rules`, supply each relevant row in effective order as `domain`, `pattern` and `rights`. Preserve duplicate rules and case. A projection of the delegate domain is sufficient when its coverage is established. Retain undetermined rows and use JSON `null` for a redacted field. Treat text placeholders such as `redacted`, `unknown` and `unavailable` as missing evidence. The reader also reserves `unverified`, `missing`, `unset`, `unspecified`, `null` and `none` as placeholders in aliases and patterns. Replacing an unknown pattern with a made-up tag changes the decision. A verified empty array means the loaded policy has no delegate rules.
- Supply effective rights as `none`, `all` or a pipe-separated combination of `read`, `write` and `execute`. The reader models the universal pattern `*` and literal ASCII tags of up to 64 characters beginning with a letter and containing letters, digits, hyphens or underscores. It preserves capitalization. For any other pattern it allows for both a match and a miss. A later wildcard can still settle the result. Input limits are 1 MiB and 1,024 rules. [Upstream rights](https://github.com/ImageMagick/ImageMagick/blob/dcec873ede2912a1b045a50fd54cd138ee5f3fa4/MagickCore/policy.h#L41-L49) · [Upstream pattern matcher](https://github.com/ImageMagick/ImageMagick/blob/dcec873ede2912a1b045a50fd54cd138ee5f3fa4/MagickCore/token.c#L613-L641)

## Release coverage

The publisher documents global delegate denial from ImageMagick 7.0.1-8 and 6.9.4-6. Rule precedence changed across releases. The reader covers the published 7.1.1 tags through 7.1.1-47 and 7.1.2 tags through 7.1.2-36, excluding 7.1.2-20 through -23, which use a different lookup. There is no 7.1.1-42 or 7.1.2-4 upstream tag in the reviewed set. Other releases return `unknown`. In the covered implementations the last matching delegate rule supplies the execute bit. With no match the default permits execute. [ImageMagick 6 policy](https://legacy.imagemagick.org/script/security-policy.php) · [7.1.1 lookup](https://github.com/ImageMagick/ImageMagick/blob/7.1.1-0/MagickCore/policy.c) · [7.1.2-20 lookup](https://github.com/ImageMagick/ImageMagick/blob/7.1.2-20/MagickCore/policy.c) · [7.1.2-36 lookup](https://github.com/ImageMagick/ImageMagick/blob/dcec873ede2912a1b045a50fd54cd138ee5f3fa4/MagickCore/policy.c#L947-L1012)

## Interpret the result

| Status | What the operator can report |
| --- | --- |
| `gap` | The effective policy permits execute for the names in `named_execute`, or for every name outside the literal set when `other_execute` is `allowed`. Report the exception and any remaining uncertainty. [Named exception](examples/gap.json) |
| `pass` | The complete saved policy denies execute throughout the delegate domain for this worker and build. A coder or module restriction only applies to its own domain. [Reversed rule order](examples/pass.json) |
| `unknown` | Read `reason` and `missing` to identify missing worker evidence or coverage. For unresolved rules, `uncertain_names` reports inconclusive literals and `other_execute` covers the remaining names. [Unconfirmed runtime policy](examples/unknown.json) |

`other_execute` is `denied` or `allowed` only when that answer holds for every remaining name. `unknown` means the rules leave that class unresolved. `unassessed` means the inputs failed a provenance or coverage check. Send the result and its evidence references to ARTEX. For `invalid_input` (exit 2), correct the JSON structure, repeated keys, normalized rule fields or input size.
