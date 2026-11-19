---
name: framework-patch-review
description: Review version and configuration evidence for named Drupal core, Next.js, Symfony HTTP Foundation and Django advisories using a supplied deployment inventory and offline checker result.
---

# Review framework package patches

Use this guide when an administrator wants to know whether a named advisory applies to the **framework package in a deployed build**. Ask for the checker result and the referenced inventory. An HTTP header, website URL, dependency constraint or workstation package list leaves the deployment version unknown.

## Run the checker

From the unpacked skill directory, the administrator can run a synthetic example with Python 3.9 or later. The script reads one JSON object on standard input and performs the comparison locally.

```sh
python3 scripts/check.py < examples/gap.json
```

Use the [affected package](examples/gap.json), [fixed package](examples/pass.json) or [incomplete inventory](examples/unknown.json) example as a template. Set `advisory` to one supported CVE. Supply one summarized `inventory` with these fields.

| Field | Evidence to supply |
| --- | --- |
| `asset`, `build`, `ref` | Redacted identifiers for the deployed application, exact build and inventory artifact. |
| `ecosystem`, `package` | `npm` and `next`, `composer` and `symfony/http-foundation`, `composer` and `drupal/core`, or `pypi` and `Django`. The checker accepts PyPI name case variants. |
| `version` | Use the release actually installed in the serving build. Use three numeric components for npm. Composer also accepts a leading `v`. For Django, `6.0` denotes `6.0.0`. Development, prerelease, modified and ambiguous version strings yield unknown. |
| `origin`, `deployment_verified` | Set `origin` to `upstream` only for the unmodified upstream package. Set `deployment_verified` to true only when the referenced artifact ties that package to this build. Distribution or custom backports require their own patch records. |

A linked deployment manifest plus the production image's package inventory can establish the version. A dependency lockfile needs a reference tying its resolved release to the deployed artifact. Keep customer names, credentials, hashes of passwords and production data out of examples and chat.

## Check the relevant feature separately

An optional `applicability` object takes `asset`, `build`, `ref` and a `conditions` object. Use a configuration or code-review reference for the same deployment and scope. Use `true` or `false` only when that source supports an answer. Omit a condition or use `null` when its state is unknown. All named conditions must be present and true to establish the feature combination. One verified false rules out that combination within the supplied scope.

| Advisory and first fixed upstream releases | Condition names and evidence |
| --- | --- |
| Drupal core CVE-2026-132165, 10.6.22, 11.3.22 and 11.4.13 on the three maintained lines named in the bulletin. | Package-only review. Leave site applicability unknown. Partial mitigations never establish a package fix. [Drupal bulletin, 18 November 2026](https://www.drupal.org/sa-core-2026-017) |
| Drupal core CVE-2026-132166, 10.6.22, 11.3.22 and 11.4.13. | Use matching upstream Composer and serving-core observations. The package result leaves site applicability unknown. [Drupal bulletin SA-CORE-2026-018](https://www.drupal.org/sa-core-2026-018) |
| Next.js CVE-2026-119349, 16.4.5. Affected releases begin at 16.0.0. | `app_router` and `binary_arguments_to_use_cache`. The app uses the App Router and passes binary arguments to a cached function. [Next.js advisory, 3 November 2026](https://github.com/vercel/next.js/security/advisories/GHSA-rhh4-g77r-r9qj) |
| Next.js CVE-2026-119351, 16.4.5. Affected releases begin at 16.2.0. | `cache_components` and `nested_cache_reads_root_params_with_pending_promises`. Cache Components are enabled and a nested cached function reads root parameters and returns a value containing pending promises. [Next.js advisory, 3 November 2026](https://github.com/vercel/next.js/security/advisories/GHSA-vc7v-qv4w-wrv8) |
| Symfony CVE-2026-118514, 5.4.56, 6.4.50, 7.4.23 and 8.1.11 on their respective release lines. | `get_rule_without_head`. Review method-scoped access rules, firewalls and custom matchers for a GET rule without HEAD. The upstream bulletin includes earlier stable releases below 5.4.56. [Symfony advisory, 4 November 2026](https://symfony.com/blog/cve-2026-118514-head-requests-bypass-the-methods-option-of-access-control-and-firewalls-incomplete-fix-for-cve-2026-45075) |
| Django CVE-2026-113593, 5.2.19, 6.0.10 and 6.1.3. | `django_page_cache_in_use` and `vary_header_present`. The assessed response uses Django's page-cache middleware or decorator and lists a request header in Vary. [Django bulletin, 3 November 2026](https://www.djangoproject.com/weblog/2026/nov/03/security-releases/) · [Django CNA record](https://www.cve.org/CVERecord?id=CVE-2026-113593) |
| Django CVE-2026-113733, 6.0.10 and 6.1.3. | `view_only_user_admin` and `affected_user_model_layout`. Review whether staff can view a user record without change permission. The model condition holds for a model other than AUTH_USER_MODEL or a configured user model inheriting its password field from a concrete parent. The supported 5.2 line falls outside this advisory's affected ranges. Older unevaluated branches remain unknown. [Django bulletin, 3 November 2026](https://www.djangoproject.com/weblog/2026/nov/03/security-releases/) · [Django CNA record](https://www.cve.org/CVERecord?id=CVE-2026-113733) |

## Reproduce the Drupal release comparison

Run the bundled synthetic inventory from this skill's directory.

```sh
python3 scripts/check.py < examples/CVE-2026-132165.json
```

The example uses upstream `drupal/core` 11.4.12. Expect `affected_version`, first fixed `11.4.13`, and `unknown` for applicability. Changing both version fields to 11.4.13 gives `vendor_fix_present`. Changing only the package version leaves patch status unknown because the records disagree.

For SA-CORE-2026-018, run the same command with `examples/CVE-2026-132166.json`. Composer reports the fixed 11.3.22 release while the serving code reports 11.4.0, which is affected on its own branch. Expect `unknown` for patch status and applicability, with the serving core flagged for follow-up.

Use the installed `drupal/core` package in the active build. Set `deployment_verified` only when the inventory is tied to that build. Record the independently observed version from its serving core code or Drupal status report in `inventory.serving_core_version`. Cite the record containing both observations. A missing or conflicting observation yields `unknown`, including when Composer reports a fixed version. Drupal documents updates where Composer metadata and the served code disagree. [Drupal update guidance](https://www.drupal.org/docs/updating-drupal/updating-drupal-core-via-composer)

The checker covers stable Composer core releases from Drupal 8 within the published affected ranges. Legacy installs can require a supported minor or major upgrade to reach the listed fix. Other branches beyond the three reviewed fix lines, prereleases, and distributor backports require their own evidence. Both checks evaluate the package and leave application exposure unknown.

When the upstream observations differ or only one parses, the checker leaves `version` empty and labels each source in `version_evidence`. If either observed release falls in the affected range, `patch_reason` names it. For example, Composer 11.4.13 with serving core 11.4.12 warrants prompt follow-up on the serving core. The deployment verdict stays `unknown` until the records agree.

## Interpret the result in ARTEX

Quote the named advisory, package, asset, build and inventory reference. Preserve the two conclusions.

- `affected_version` means the supplied upstream release falls in the published affected range. Record the first fixed release for that range.
- `vendor_fix_present` means the reviewed release includes the documented upstream fix on its covered release line.
- `outside_affected_range` means the verified release predates the introduced range or is on a supported line excluded by the vendor record. Keep this distinct from an applied fix.
- `unknown` means the checker needs better inventory, provenance, a supported version format or information about that release line.
- `conditions_present`, `conditions_absent` and `unknown` describe the recorded deployment features. Cite the configuration reference when available. An affected package with matching features merits review of the relevant data or access policy. Proof of disclosure or unauthorized access needs independent evidence.

Report an `invalid_input` result as a request to correct the input. Retest against a new deployed inventory after an upgrade. These advisory records were reviewed on 19 November 2026.
