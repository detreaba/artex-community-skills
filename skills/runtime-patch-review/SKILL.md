---
name: runtime-patch-review
description: Interpret a PHP or Node.js serving-process inventory for a supported vendor advisory. Distinguish the deployed patch level from evidence about the application's configuration.
---

# Review the serving runtime

Interpret the result from this skill's offline checker. Ask for the administrator's checker JSON, an asset alias, and a build or deployment reference. When they have an inventory but haven't run the checker, share the command below. A URL, browser bundle, package lockfile, or development workstation version leaves the production runtime patch status unknown.

## Prepare the input

Run this from the skill directory with Python 3.9 or later. The example describes a synthetic Node.js deployment.

```sh
python3 scripts/check.py < examples/gap.json
```

For a real review, supply one supported `advisory` and an `inventory` object with `asset`, `build`, `ref`, `runtime` (`php` or `node`), `version`, `origin`, and `serving_process_verified`. Set that last field true only when evidence identifies the running process. Use `upstream` only when the inventory establishes the release's origin. A distribution or custom build requires its vendor's own package and backport information. Use short redacted aliases for these references. The checker reads stdin and makes no network requests.

Optional `applicability` evidence has its own `asset`, `build`, `ref`, and `conditions`. Match the asset and build to the inventory. Supply booleans only for conditions that a configuration review establishes. The initial rules cover the following advisories.

| Advisory | Configuration evidence |
| --- | --- |
| PHP session handling, CVE-2026-115560 | `upload_progress_enabled` and `shared_session_serializer_mismatch`. Check whether processes sharing session storage use incompatible serializer settings. [PHP advisory](https://github.com/php/php-src/security/advisories/GHSA-658j-r8rw-q6mx) |
| Node.js HTTP/2 resource leak, CVE-2026-123865 | `node_handles_http2` refers to the serving Node.js process. An edge proxy can terminate HTTP/2 independently. [Node.js bulletin](https://nodejs.org/en/blog/vulnerability/november-2026-security-releases) |

## Explain the result

Report the named advisory, build, evidence references, and `patch_status`. For `affected_version`, identify the first fixed release on that branch and request a fresh inventory after updating. For `vendor_fix_present`, limit the statement to this patch. For `unknown`, use `patch_reason` to request the missing evidence. If the checker emits `invalid_input`, request a corrected record or a vendor assessment for an unsupported CVE.

Report `applicability` separately. A verified affected version warrants patch review even when the relevant configuration is absent. When an application feature is present, further case-specific evidence is needed to assess application impact. Preserve the checker's limitations alongside its result.

The fixtures show an affected upstream release, a patched release, and an unverified inventory. [Affected fixture](examples/gap.json) · [Patched fixture](examples/pass.json) · [Unknown fixture](examples/unknown.json)
