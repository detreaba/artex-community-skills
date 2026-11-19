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

Optional `applicability` evidence has its own `asset`, `build`, `ref`, and `conditions`. Match the asset and build to the inventory. Supply booleans only for conditions that a configuration review establishes.

| Advisory | Published | Configuration evidence |
| --- | --- | --- |
| PHP-FPM status display, CVE-2026-129292 | 19 Nov 2026 | `fpm_status_enabled`, `request_metadata_reaches_pool`, `full_status_rendered_as_html`. Check whether untrusted request metadata can reach the fields displayed in this pool's full status output and whether anyone renders it as HTML. Access restrictions on the status page alone leave these questions open. [PHP advisory](https://github.com/php/php-src/security/advisories/GHSA-3mg3-cr28-46gc) |
| PHP-CGI path handling, CVE-2026-129538 | 19 Nov 2026 | `php_cgi_serves_requests`, `cgi_fix_pathinfo_enabled`, `affected_frontend_path_mapping`. Use the web server mapping and effective CGI configuration to establish whether the documented path inconsistency is possible. Either CGI or FastCGI can invoke the php-cgi binary. A deployment served exclusively by PHP-FPM or the Apache PHP module has `php_cgi_serves_requests=false`. [PHP advisory](https://github.com/php/php-src/security/advisories/GHSA-5j3f-64r7-f564) |
| PHP session handling, CVE-2026-115560 | 19 Nov 2026 | `upload_progress_enabled` and `shared_session_serializer_mismatch`. Check whether processes sharing session storage use incompatible serializer settings. [PHP advisory](https://github.com/php/php-src/security/advisories/GHSA-658j-r8rw-q6mx) |
| Node.js HTTP/2 resource leak, CVE-2026-123865 | 11 Nov 2026 | `node_handles_http2` refers to the serving Node.js process. An edge proxy can terminate HTTP/2 independently. [Node.js bulletin](https://nodejs.org/en/blog/vulnerability/november-2026-security-releases) |
| Node.js bundled Brotli decoder, CVE-2026-111497 | 21 Oct 2026 | Set `node_decodes_untrusted_brotli` to true when the serving process passes externally supplied data to the Brotli decoder in `node:zlib`, directly or through a dependency. Include compressed responses received by the application's HTTP client. A proxy's HTTP/2 settings or evidence of response compression alone leaves decoding unknown. [Node.js bulletin](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases) |

For CVE-2026-111497, use `origin: "upstream"` when the running executable comes from the official Node.js release with its bundled decoder. The recorded first fixes are 22.23.4, 24.22.1 and 26.12.1, each on its own major line. A distribution or custom build can link a separately patched system Brotli. Supply that build's actual origin and consult its distributor when the checker returns `unknown`. [Node.js release ranges](https://github.com/nodejs/security-wg/blob/main/vuln/core/204.json) · [Red Hat's package assessment](https://access.redhat.com/security/cve/cve-2026-111497)

From the skill directory, run `python3 scripts/check.py < examples/CVE-2026-111497.json`. The example records upstream v24.22.0 and an observed decoder path. Expect `affected_version`, first fix `24.22.1`, and `conditions_present`. [Synthetic Node.js inventory](examples/CVE-2026-111497.json)

## Explain the result

Report the named advisory, build, evidence references, and `patch_status`. For `affected_version`, identify the first fixed release on that branch and request a fresh inventory after updating. For `vendor_fix_present`, limit the statement to this patch. For `unknown`, use `patch_reason` to request the missing evidence. If the checker emits `invalid_input`, request a corrected record or a vendor assessment for an unsupported CVE.

Report `applicability` separately. A verified affected version warrants patch review even when the relevant configuration is absent. When an application feature is present, further case-specific evidence is needed to assess application impact. Preserve the checker's limitations alongside its result.

The fixtures show an affected upstream release, a patched release, and an unverified inventory. [Affected fixture](examples/gap.json) · [Patched fixture](examples/pass.json) · [Unknown fixture](examples/unknown.json)
