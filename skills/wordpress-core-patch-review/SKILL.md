---
name: wordpress-core-patch-review
description: Review whether a deployed WordPress core release includes the vendor's fix for four CISA KEV-listed WordPress core advisories, using a supplied core version record, a core checksum check and an offline checker result.
---

# Review WordPress core patches

Use this guide when an administrator wants to know whether the **WordPress core running in a deployed site** includes the WordPress Security Team's fix for a named advisory. All four advisories below are listed in the CISA Known Exploited Vulnerabilities catalog, so an affected result is urgent. Plugins and themes are outside this skill.

## Collect the evidence

Read every value from the deployed site or its exact build. A staging copy, a backup or an auto-update setting leaves the running release unknown.

| Field | Evidence to supply |
| --- | --- |
| `asset`, `build`, `ref` | Redacted identifiers for the site, the deployed build and the record holding the version. |
| `version` | `$wp_version` from the deployed `wp-includes/version.php`, the output of `wp core version` on the site, or **Site Health → Info → WordPress → Version**. WordPress writes a branch's first release as `7.1`; `7.1.0` means the same release. Beta, RC and nightly versions return unknown. |
| `origin` | `upstream` only for an unmodified wordpress.org release, including Composer installs of the official package. A host-maintained or patched core needs that maintainer's own record. |
| `deployment_verified` | True only when the referenced record ties the version to this deployed build. |
| `core_checksums_verified` | True only when `wp core verify-checksums` (or an equivalent comparison with the wordpress.org checksums for this release) passed on the same build. A fixed or not-affected verdict requires it. An affected version does not. |

Keep customer names, credentials and production data out of examples and chat.

## Run the checker

From the unpacked skill directory, with Python 3.9 or later:

```sh
python3 scripts/check.py < examples/gap.json
```

Use the [affected](examples/gap.json), [fixed](examples/pass.json) or [unknown](examples/unknown.json) example as a template. Set `advisory` to one supported CVE and run the checker once per advisory. The checker reads one JSON object on stdin and makes no network requests.

| Advisory | First fixed release per branch | Notes |
| --- | --- | --- |
| CVE-2026-60137, facilitated SQL injection in `WP_Query` `author__not_in` ([GHSA-fpp7-x2x2-2mjf](https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-fpp7-x2x2-2mjf), 17 July 2026, KEV 21 July 2026) | 6.8.6, 6.9.5, 7.0.2. The 7.1 branch shipped with the fix. | The [7.0.2 release post](https://wordpress.org/news/2026/07/wordpress-7-0-2-release/) states that versions before 6.8 are not affected. On 6.9 and later it chains with CVE-2026-63030. |
| CVE-2026-63030, REST API batch-route confusion leading to remote code execution ([GHSA-ff9f-jf42-662q](https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-ff9f-jf42-662q), 17 July 2026, KEV 21 July 2026) | 6.9.5, 7.0.2. The 7.1 branch shipped with the fix. | The 6.8 branch and earlier releases are not affected. |
| CVE-2026-87902, page-template path traversal leading to conditional remote code execution ([GHSA-7hp8-65ch-5whp](https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-7hp8-65ch-5whp), 22 September 2026, KEV 25 September 2026) | The fix is on 25 branches, from 7.1.2, 7.0.6 and 6.9.9 back to 4.7.37. See the checker table. | Releases before 4.7 received no backport. The CNA record lists them as affected, so the checker reports them with 7.1.2 as the fix. Optional conditions: `theme_has_page_prefixed_directory` (the active child or parent theme has a top-level directory starting with `page-`, as in Twenty Twelve, Twenty Fourteen, Neve, Hestia and Sydney) and `includable_php_target_readable` (the web server can read a local PHP file usable for inclusion, such as PEAR's `pearcmd.php` with `register_argc_argv` on). |
| CVE-2026-119977, upgrade-window race during full-package core updates ([GHSA-4w3m-c66w-69mg](https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-4w3m-c66w-69mg), 28 October 2026, KEV 3 November 2026) | The fix is on 25 branches, from 7.1.4, 7.0.8 and 6.9.11 back to 4.7.39. | The vendor advisory carries no CVE ID and rates it low. The [CNA record](https://www.cve.org/CVERecord?id=CVE-2026-119977) assigns the CVE with the same 25 branch ranges. Releases before 4.7 remain unknown. |

Optional `applicability` evidence takes `asset`, `build`, `ref` and `conditions`, using the same build and redacted references. Only CVE-2026-87902 accepts conditions. Use `true` or `false` only when a review of the active theme and the server establishes the answer. Both conditions true establishes the documented pre-conditions. One verified false rules them out within that scope.

## Interpret the result in ARTEX

Quote the advisory, its vendor advisory ID, the site, build and evidence references, and the KEV date.

- `affected_version`: the deployed release is inside the vendor's affected range. Name `first_fixed_in_range` as the upgrade target and treat the case as urgent, because the advisory is KEV-listed. For CVE-2026-119977, exposure arises during full-package core updates on affected releases.
- `vendor_fix_present`: the release includes the vendor's fix on its branch, and its core files match the wordpress.org checksums.
- `outside_affected_range`: the vendor states that this release line is not affected. This is not the same as an applied fix.
- `unknown`: the evidence is not enough. Use `patch_reason` to request it:
  - the deployed version record;
  - an upstream origin;
  - a stable release;
  - a checksum verification;
  - a reviewed branch.
- `applicability` is reported separately: `conditions_present`, `conditions_absent` or `unknown`. Proof of exploitation or compromise needs separate evidence.

Report an `invalid_input` result as a request to correct the input. Retest with a new version record and checksum check after updating. These four advisory records were reviewed on 19 November 2026.
