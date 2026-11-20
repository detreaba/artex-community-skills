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
| PHP session files, CVE-2026-126714 | 19 Nov 2026 | `session_files_handler_in_use` is true when any pool or application stores sessions through PHP's built-in `files` handler, which is the default. That includes a custom handler that extends `SessionHandler` and passes calls to its parent, which wraps the handler set by `session.save_handler`. Answer `false` only with a verified storage path that isn't `files`, such as Redis, Memcached or a database, for every pool and application; a handler's registration name alone isn't enough. Disabling upload progress removes one input path but doesn't fix the handler. [PHP advisory](https://github.com/php/php-src/security/advisories/GHSA-fm2m-fjf5-v3cp) · [SessionHandler](https://www.php.net/manual/en/class.sessionhandler.php) |
| PHP-FPM request smuggling, CVE-2026-129289 | 19 Nov 2026 | `backend_connection_reuse_enabled` is true when any front end that can reach the PHP-FPM or LSAPI listener keeps backend connections open across requests, for example nginx `fastcgi_keep_conn on`, Apache `mod_proxy_fcgi` with `enablereuse=on`, or HAProxy with retained FastCGI connections. OpenLiteSpeed kept LSAPI connections regardless of configuration until commit `c30bdf86` (7 Nov 2026), which honours `persistConn 0`; that setting counts only on a build shown to contain the change. Answer `false` only when the front end's build and configuration are identified and every client able to reach the listener closes its backend connection after each request. If only the SAPI or front-end name is known, leave the flag unset. [PHP advisory](https://github.com/php/php-src/security/advisories/GHSA-qc49-hpvq-g2w6) · [OpenLiteSpeed change](https://github.com/litespeedtech/openlitespeed/commit/c30bdf86bf0e919ce1cea1011322d8bfc3ef185a) |
| PHP timezone cache, CVE-2026-129496 | 19 Nov 2026 | `php_error_log_to_file` is true when PHP's `error_log` names a file in the configuration loaded when the PHP master process or Apache parent starts, or in any pool override. Answer `false` only when that configuration and every pool override leave `error_log` unset or set it to `syslog`. FPM's own error log doesn't count. [PHP advisory](https://github.com/php/php-src/security/advisories/GHSA-gr4f-wgx5-jpfv) |
| PHP session shutdown, CVE-2026-129481 | 19 Nov 2026 | No configuration condition is documented as necessary, so `applicability` stays `unknown`. PHP 8.2 and earlier don't contain the affected field. [PHP advisory](https://github.com/php/php-src/security/advisories/GHSA-g3vh-838c-65v7) |
| PHP magic-method backtraces, CVE-2026-129474 | 19 Nov 2026 | `fatal_error_backtraces_enabled` and `exception_args_included`. The second flag is true when `zend.exception_ignore_args=0`; PHP's built-in default is 0, and `php.ini-production` sets 1. Answer `false` for `fatal_error_backtraces_enabled` only when every pool and application override sets `fatal_error_backtraces=0`, and for `exception_args_included` only when every pool and application override sets `zend.exception_ignore_args=1`. In both cases, request-specific configuration must not be able to change the setting. The `fatal_error_backtraces` setting exists from PHP 8.5.0, so leave `fatal_error_backtraces_enabled` unset on earlier branches. [PHP advisory](https://github.com/php/php-src/security/advisories/GHSA-8mjj-2r7p-4hg2) |
| PHP fatal-error backtrace after shutdown, CVE-2026-129182 | 19 Nov 2026 | `fatal_error_backtraces_enabled`, defined as for CVE-2026-129474: answer `false` only when every pool and application override sets `fatal_error_backtraces=0` and request-specific configuration can't turn it back on. PHP 8.5 enables it by default, as GHSA-8mjj-2r7p-4hg2 states, and the setting doesn't exist before 8.5.0, so leave the flag unset on earlier branches. [PHP advisory](https://github.com/php/php-src/security/advisories/GHSA-2fjv-p558-g82m) |
| PHP-FPM status display, CVE-2026-129292 | 19 Nov 2026 | `fpm_status_enabled`, `request_metadata_reaches_pool`, `full_status_rendered_as_html`. Check whether untrusted request metadata can reach the fields displayed in this pool's full status output and whether anyone renders it as HTML. Access restrictions on the status page alone leave these questions open. [PHP advisory](https://github.com/php/php-src/security/advisories/GHSA-3mg3-cr28-46gc) |
| PHP-CGI path handling, CVE-2026-129538 | 19 Nov 2026 | `php_cgi_serves_requests`, `cgi_fix_pathinfo_enabled`, `affected_frontend_path_mapping`. Use the web server mapping and effective CGI configuration to establish whether the documented path inconsistency is possible. Either CGI or FastCGI can invoke the php-cgi binary. A deployment served exclusively by PHP-FPM or the Apache PHP module has `php_cgi_serves_requests=false`. [PHP advisory](https://github.com/php/php-src/security/advisories/GHSA-5j3f-64r7-f564) |
| PHP session handling, CVE-2026-115560 | 19 Nov 2026 | `upload_progress_enabled` and `shared_session_serializer_mismatch`. Check whether processes sharing session storage use incompatible serializer settings. [PHP advisory](https://github.com/php/php-src/security/advisories/GHSA-658j-r8rw-q6mx) |
| Node.js HTTP/2 resource leak, CVE-2026-123865 | 11 Nov 2026 | `node_handles_http2` refers to the serving Node.js process. An edge proxy can terminate HTTP/2 independently. [Node.js bulletin](https://nodejs.org/en/blog/vulnerability/november-2026-security-releases) |
| PHP out-of-memory handling, CVE-2026-109618 | 21 Oct 2026 | `php_serves_web_requests` records whether the identified process handles web requests. PHP includes FPM, Apache mod_php, CGI, FrankenPHP and LiteSpeed. A memory-limit setting alone leaves applicability unknown. [PHP advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) · [PHP release guidance](https://www.php.net/archive/2026.php#2026-10-21-5) |
| PHP stale request state, CVE-2026-109619 | 21 Oct 2026 | Supply `php_serves_web_requests` and `worker_reused_across_requests` for the same serving deployment. Set the second field when the worker can handle successive PHP request lifecycles. A pool policy that retires each worker after one request establishes `false`. The output of a separate `php -v` leaves both the serving binary and its lifecycle unknown. [PHP advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) |

Use this package's `scripts/check.py` for the PHP 8.6 decision. The 8.6.0 release lists the fixes for CVE-2026-115560, CVE-2026-126714, CVE-2026-129182, CVE-2026-129289, CVE-2026-129292, CVE-2026-129474, CVE-2026-129481, CVE-2026-129496 and CVE-2026-129538. For a verified stable upstream 8.6.x serving process, the checker reports `vendor_fix_present` and first fixed release `8.6.0`. A release candidate or a distributor build leaves patch status `unknown`. For CVE-2026-115560, effective upload-progress and serializer settings can still give `conditions_present` on a patched process. [PHP 8.6.0 ChangeLog](https://www.php.net/ChangeLog-8.php#8.6.0) · [Tagged release NEWS](https://github.com/php/php-src/blob/8aaada3f9605d81a38b8240f93c7389dfbc77ef9/NEWS)

For example, this synthetic upstream inventory gives `affected_version` and the first fixed PHP 8.4 release, `8.4.27`. Applicability stays `unknown` until the owner supplies evidence of the process's web-serving role. For PHP 8.1 and older, a backport requires its own patch record. The ranges `< 8.2.36` in CVE-2026-115560, CVE-2026-126714, CVE-2026-129289, CVE-2026-129292, CVE-2026-129496 and CVE-2026-129538 also reach end-of-life lines, back to the introduction point each advisory states. PHP has published no fix for those lines, but the checker still reports them `unknown`.

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

Report the named advisory, build, evidence references, and `patch_status`. For `affected_version`, identify the first fixed release on that branch and request a fresh inventory after updating. For `vendor_fix_present`, limit the statement to this patch. For `unknown`, use `patch_reason` to request the missing evidence.

`outside_affected_range` means the vendor explicitly places this upstream branch outside the advisory's affected range. Quote `patch_reason`, which carries the vendor's statement. The result applies to that advisory only and is not a fix verdict for any other.
- **Where it applies:** published releases only.
  - CVE-2026-129481 on PHP 8.2 and earlier;
  - CVE-2026-129182 on PHP 8.4 and earlier;
  - CVE-2026-129474 on PHP 8.2 to 8.4. For this one, the vendor says the underlying error is present but has no known remote trigger, so mention its limitation.
- **What counts as published:** a release in PHP's release index on php.net, or a later patch on a branch PHP still supports.
  - The index has no 6.x, no 7.5 and no 8.1.35, and it skips a few patch numbers such as 8.4.0 and 8.3.18.
  - A version it doesn't list reads `unknown`, so reconcile the inventory with the serving binary.
- **What stays `unknown`:** any line the vendor doesn't name, such as 8.1 for CVE-2026-129474, and every distributor build.

If the checker emits `invalid_input`, request a corrected record or a vendor assessment for an unsupported CVE.

Report `applicability` separately. A verified affected version warrants patch review even when the relevant configuration is absent. When an application feature is present, further case-specific evidence is needed to assess application impact. Preserve the checker's limitations alongside its result.

The fixtures show an affected upstream release, a patched release, and an unverified inventory. [Affected fixture](examples/gap.json) · [Patched fixture](examples/pass.json) · [Unknown fixture](examples/unknown.json)
