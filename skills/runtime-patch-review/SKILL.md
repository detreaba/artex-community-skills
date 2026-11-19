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
| PHP out-of-memory handling, CVE-2026-109618 | 21 Oct 2026 | `php_serves_web_requests` records whether the identified process handles web requests. PHP includes FPM, Apache mod_php, CGI, FrankenPHP and LiteSpeed. A memory-limit setting alone leaves applicability unknown. [PHP advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) · [PHP release guidance](https://www.php.net/archive/2026.php#2026-10-21-5) |
| PHP stale request state, CVE-2026-109619 | 21 Oct 2026 | Supply `php_serves_web_requests` and `worker_reused_across_requests` for the same serving deployment. Set the second field when the worker can handle successive PHP request lifecycles. A pool policy that retires each worker after one request establishes `false`. The output of a separate `php -v` leaves both the serving binary and its lifecycle unknown. [PHP advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) |

Use this package's `scripts/check.py` for the PHP 8.6 decision. The 8.6.0 release lists the fixes for CVE-2026-115560, CVE-2026-129292 and CVE-2026-129538. For a verified stable upstream 8.6.x serving process, the checker reports `vendor_fix_present` and first fixed release `8.6.0`. A release candidate or a distributor build leaves patch status `unknown`. For the session advisory, effective upload-progress and serializer settings can still give `conditions_present` on a patched process. [PHP 8.6.0 ChangeLog](https://www.php.net/ChangeLog-8.php#8.6.0) · [Tagged release NEWS](https://github.com/php/php-src/blob/8aaada3f9605d81a38b8240f93c7389dfbc77ef9/NEWS)

For example, this synthetic upstream inventory gives `affected_version` and the first fixed PHP 8.4 release, `8.4.27`. Applicability stays `unknown` until the owner supplies evidence of the process's web-serving role. For PHP 8.1 and older, a backport requires its own patch record.

```json
{
  "advisory": "CVE-2026-109618",
  "inventory": {
    "asset": "training-portal", "build": "release-4", "ref": "runtime-record-4",
    "runtime": "php", "version": "8.4.26", "origin": "upstream",
    "serving_process_verified": true
  }
}
```

For CVE-2026-109619, this synthetic worker-pool record gives `affected_version`, first fixed `8.5.12`, and `conditions_present`. Omitting the worker reuse observation leaves applicability `unknown`.

```json
{
  "advisory": "CVE-2026-109619",
  "inventory": {"asset": "portal", "build": "image-12", "ref": "process-7",
                "runtime": "php", "version": "8.5.11", "origin": "upstream", "serving_process_verified": true},
  "applicability": {"asset": "portal", "build": "image-12", "ref": "pool-record-7",
                    "conditions": {"php_serves_web_requests": true, "worker_reused_across_requests": true}}
}
```

## Explain the result

Report the named advisory, build, evidence references, and `patch_status`. For `affected_version`, identify the first fixed release on that branch and request a fresh inventory after updating. For `vendor_fix_present`, limit the statement to this patch. For `unknown`, use `patch_reason` to request the missing evidence. If the checker emits `invalid_input`, request a corrected record or a vendor assessment for an unsupported CVE.

Report `applicability` separately. A verified affected version warrants patch review even when the relevant configuration is absent. When an application feature is present, further case-specific evidence is needed to assess application impact. Preserve the checker's limitations alongside its result.

The fixtures show an affected upstream release, a patched release, and an unverified inventory. [Affected fixture](examples/gap.json) · [Patched fixture](examples/pass.json) · [Unknown fixture](examples/unknown.json)
