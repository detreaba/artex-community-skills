---
name: framework-patch-review
description: Review version and configuration evidence for named React Server Components, Craft CMS, Livewire, Drupal core, Next.js, Symfony HTTP Foundation and Django advisories using a supplied deployment inventory and offline checker result.
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
| `ecosystem`, `package` | For Composer, use `composer` and the package name `craftcms/cms`, `livewire/livewire`, `symfony/http-foundation` or `drupal/core`. Other supported pairs are `npm` with the named React server-dom package or `next` and `pypi` with `Django`. The checker accepts PyPI name case variants. |
| `version` | Use the release actually installed in the serving build. Use three numeric components for npm. Composer also accepts a leading `v`. For Django, `6.0` denotes `6.0.0`. The Craft check recognizes published four-part releases and the initial release candidates on its reviewed lines. The Livewire check recognizes the published betas at its affected lower boundary. |
| `origin`, `deployment_verified` | Set `origin` to `upstream` only for the unmodified upstream package. Set `deployment_verified` to true only when the referenced artifact ties that package to this build. Distribution or custom backports require their own patch records. |

A linked deployment manifest plus the production image's package inventory can establish the version. A dependency lockfile needs a reference tying its resolved release to the deployed artifact. Keep customer names, credentials, hashes of passwords and production data out of examples and chat.

## Check the relevant feature separately

An optional `applicability` object takes `asset`, `build`, `ref` and a `conditions` object. Use a configuration or code-review reference for the same deployment and scope. Use `true` or `false` only when that source supports an answer. Omit a condition or use `null` when its state is unknown. A positive applicability result requires evidence for every prerequisite. One verified false rules out that combination within the supplied scope.

| Advisory and first fixed upstream releases | Condition names and evidence |
| --- | --- |
| Craft CMS CVE-2024-56145. First fixes are 3.9.14, 4.13.2 and 5.5.2. | `php_register_argc_argv_enabled`. Use the effective PHP setting on the web-serving build. A CLI export alone leaves it unknown. Set false only when the effective setting is disabled across every serving pool and applicable per-directory override for the sites in scope. [Craft advisory](https://github.com/craftcms/cms/security/advisories/GHSA-2p6p-9rc9-62j9) |
| Craft CMS CVE-2025-23209. First documented fixes are 4.13.8 and 5.5.8. | `active_craft_key_compromise_confirmed`. A same-build incident record can confirm that the active key was compromised. A false flag means the compromise was unconfirmed and leaves applicability unknown. Supply only the redacted incident reference. [Craft advisory](https://github.com/craftcms/cms/security/advisories/GHSA-x684-96hh-833x) |
| Craft CMS CVE-2025-32432. First fixes are 3.9.15, 4.14.15 and 5.6.17. | Package-only review. Record any separately installed mitigation extension in the report. It leaves the installed core version and the package verdict unchanged. [Craft advisory](https://github.com/craftcms/cms/security/advisories/GHSA-f3gw-9ww9-jmc3) · [Vendor mitigation extension](https://github.com/craftcms/security-patches) |
| Livewire CVE-2025-54068, 3.6.4. The affected interval begins at 3.0.0-beta.1. | `livewire_component_mounted`. Mounting is one prerequisite. Livewire describes an additional configuration requirement whose details are undisclosed. [Livewire advisory](https://github.com/livewire/livewire/security/advisories/GHSA-29cq-5w36-x7w3) |
| Drupal core CVE-2026-9082. First packaged fixes are 10.4.10, 10.5.10, 10.6.9, 11.1.10, 11.2.12 and 11.3.10. | `serving_database_uses_postgresql`. Use the effective database driver for the running site. A negative finding must cover every serving site and connection in scope. [Drupal bulletin, 20 May 2026](https://www.drupal.org/sa-core-2026-004) |
| Drupal core CVE-2026-132165, 10.6.22, 11.3.22 and 11.4.13 on the three maintained lines named in the bulletin. | Package-only review. Leave site applicability unknown. Partial mitigations never establish a package fix. [Drupal bulletin, 18 November 2026](https://www.drupal.org/sa-core-2026-017) |
| Drupal core CVE-2026-132166, 10.6.22, 11.3.22 and 11.4.13. | Use matching upstream Composer and serving-core observations. The package result leaves site applicability unknown. [Drupal bulletin SA-CORE-2026-018](https://www.drupal.org/sa-core-2026-018) |
| Next.js CVE-2026-119349, 16.4.5. Affected releases begin at 16.0.0. | `app_router` and `binary_arguments_to_use_cache`. The app uses the App Router and passes binary arguments to a cached function. [Next.js advisory, 3 November 2026](https://github.com/vercel/next.js/security/advisories/GHSA-rhh4-g77r-r9qj) |
| Next.js CVE-2026-119351, 16.4.5. Affected releases begin at 16.2.0. | `cache_components` and `nested_cache_reads_root_params_with_pending_promises`. Cache Components are enabled and a nested cached function reads root parameters and returns a value containing pending promises. [Next.js advisory, 3 November 2026](https://github.com/vercel/next.js/security/advisories/GHSA-vc7v-qv4w-wrv8) |
| Symfony CVE-2026-118514, 5.4.56, 6.4.50, 7.4.23 and 8.1.11 on their respective release lines. | `get_rule_without_head`. Review method-scoped access rules, firewalls and custom matchers for a GET rule without HEAD. The upstream bulletin includes earlier stable releases below 5.4.56. [Symfony advisory, 4 November 2026](https://symfony.com/blog/cve-2026-118514-head-requests-bypass-the-methods-option-of-access-control-and-firewalls-incomplete-fix-for-cve-2026-45075) |
| Django CVE-2026-113593, 5.2.19, 6.0.10 and 6.1.3. | `django_page_cache_in_use` and `vary_header_present`. The assessed response uses Django's page-cache middleware or decorator and lists a request header in Vary. [Django bulletin, 3 November 2026](https://www.djangoproject.com/weblog/2026/nov/03/security-releases/) · [Django CNA record](https://www.cve.org/CVERecord?id=CVE-2026-113593) |
| Django CVE-2026-113733, 6.0.10 and 6.1.3. | `view_only_user_admin` and `affected_user_model_layout`. Review whether staff can view a user record without change permission. The model condition holds for a model other than AUTH_USER_MODEL or a configured user model inheriting its password field from a concrete parent. The supported 5.2 line falls outside this advisory's affected ranges. Older unevaluated branches remain unknown. [Django bulletin, 3 November 2026](https://www.djangoproject.com/weblog/2026/nov/03/security-releases/) · [Django CNA record](https://www.cve.org/CVERecord?id=CVE-2026-113733) |

## Check a deployed Craft CMS release

Use the installed `craftcms/cms` entry from the serving build. A project template such as `craftcms/craft`, an update constraint or a plugin's version leaves the core release unresolved. The bundled list covers stable Craft 3, 4 and 5 tags, including four-part releases, and the published 3.0.0, 4.0.0 and 5.0.0 release candidates. An unlisted version or other preview needs a separate publisher check. [Packagist release index](https://repo.packagist.org/p2/craftcms/cms.json)

Run `python3 scripts/check.py < examples/CVE-2025-23209.json`. The fixture uses 5.5.6.1 with a confirmed compromise of the active key. Expect `unknown` for patch status and `conditions_present` for applicability. The bulletin stops the affected interval before 5.5.5 and names 5.5.8 as fixed. The published intervening tags are 5.5.5, 5.5.6, 5.5.6.1 and 5.5.7. The fix appears between 5.5.7 and 5.5.8. The advisory names Craft 4 and 5. A published Craft 3 tag also gives `unknown` with no first fix. Quote the applicable evidence gap in the report. A routine rotation or an incident involving only a previous key leaves the active key's status unknown. [Project advisory](https://github.com/craftcms/cms/security/advisories/GHSA-x684-96hh-833x) · [Publisher release comparison](https://github.com/craftcms/cms/compare/5.5.7...5.5.8)

The two other fixtures show why the advisory ID matters. Craft 3.9.14 contains the fix for CVE-2024-56145 and is affected by CVE-2025-32432. For the former advisory, the Craft 3 affected range begins at stable 3.0.0 and earlier release candidates give `unknown`. The latter includes 3.0.0-RC1. [PHP configuration fixture](examples/CVE-2024-56145.json) · [Core package fixture](examples/CVE-2025-32432.json)

## Check a deployed React Server Components package

For CVE-2025-55182, identify the exact `react-server-dom-webpack`, `react-server-dom-turbopack` or `react-server-dom-parcel` package that the server resolves. Use a separate inventory record for each installed copy or deployment. The publisher lists four affected stable versions. [React bulletin](https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components) · [Publisher advisory](https://github.com/react/react/security/advisories/GHSA-fv66-9v8q-g76r)

| Stable branch | Affected | First fixed | Reviewed npm distributions |
| --- | --- | --- | --- |
| 19.0 | 19.0.0 | 19.0.1 | Webpack and Turbopack |
| 19.1 | 19.1.0 and 19.1.1 | 19.1.2 | Webpack, Turbopack and Parcel |
| 19.2 | 19.2.0 | 19.2.1 | Webpack, Turbopack and Parcel |

Supply `inventory.serving_package` with the same `asset`, `build`, `package` and `version` as the package inventory. Use a distinct `ref` for a saved server-resolution and content-verification record. Set `source` to `server_resolver`. Set `contents_verified` to true only when the record establishes that the resolved package’s deployed contents match the authenticated npm distribution. Enter that tarball’s complete `sha512-` integrity string. Reading integrity from a lockfile establishes the expected download. A content comparison or verified immutable-build attestation supplies evidence for what serves requests. A private framework bundle, a locally modified package or a client dependency alone leaves the upstream patch status unknown. [Downstream Next.js bulletin](https://nextjs.org/blog/CVE-2025-66478)

For CVE-2025-55182 the checker compares the package name, version and integrity with 83 published archives on the three named branches. Parcel has no stable npm 19.0 release. Unlisted builds, canaries and the later 19.3 line give `unknown` with an empty first fix. Each verdict concerns CVE-2025-55182. Consult current publisher guidance when choosing an upgrade. [Webpack registry](https://registry.npmjs.org/react-server-dom-webpack) · [Turbopack registry](https://registry.npmjs.org/react-server-dom-turbopack) · [Parcel registry](https://registry.npmjs.org/react-server-dom-parcel)

Run `python3 scripts/check.py < examples/CVE-2025-55182.json`. The synthetic example reports Webpack 19.1.1 as affected, first fixed in 19.1.2. For deployment applicability, record `server_supports_react_server_components` against that same build. A server can support RSC even when the application defines no Server Function endpoints. A verified client-only build or a server verified to lack RSC support establishes an absent condition. Missing feature evidence leaves it unknown. [Example](examples/CVE-2025-55182.json) · [React deployment scope](https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components)

### October 2026 React advisory

For CVE-2026-126187, use the same installed inventory and verified server package evidence. The first fixes are 19.0.9, 19.1.10, 19.2.9 and 19.3.1. The affected versions start at patch zero on each line and end immediately before the corresponding fix. The reviewed catalog covers 89 published npm archives across the four lines. Parcel has no published stable 19.0 archive. A framework-bundled copy needs its own downstream advisory and build evidence. [React advisory](https://github.com/react/react/security/advisories/GHSA-xqc2-xf4c-x3h3) · [CNA record](https://www.cve.org/CVERecord?id=CVE-2026-126187)

Record `server_supports_react_server_components` and `publisher_response_condition_present` separately. The second field records whether a same-build review established the application's response condition described in the October advisory. A negative finding needs to cover every application response in the named scope. Supply a redacted review reference. The example uses a verified Webpack 19.3.0 archive and confirms RSC support alone. Expect `affected_version`, first fix 19.3.1 and `unknown` applicability. [Example](examples/CVE-2026-126187.json)

## Check a deployed Livewire component

Run `python3 scripts/check.py < examples/CVE-2025-54068.json`. The example ties Composer's `livewire/livewire` v3.6.3 to a serving build with a mounted component. Expect `affected_version`, first fix `3.6.4`, and `unknown` applicability. The project's advisory range field omits 3.6.3. The CNA record and reviewed advisory include it, and the publisher released the fix in the single commit from v3.6.3 to v3.6.4. [CNA record](https://www.cve.org/CVERecord?id=CVE-2025-54068) · [Reviewed advisory](https://github.com/advisories/GHSA-29cq-5w36-x7w3) · [Publisher release](https://github.com/livewire/livewire/releases/tag/v3.6.4) · [Release comparison](https://github.com/livewire/livewire/compare/v3.6.3...v3.6.4)

Set `livewire_component_mounted` to `false` only when a same-build review covers every application in scope and rules out all mounts. A check of one route, tenant or application leaves the condition unknown for the rest. A verified mount alone also leaves applicability unknown because the publisher did not identify the additional configuration.

The offline release list was checked on 20 November 2026. Published stable releases on the 0.x, 1.x and 2.x lines fall outside the advisory. The checker evaluates published stable v3 releases and the eleven published 3.0.0 betas. The publisher’s advisory predates v4 and provides no patch determination for that line. Report a v4 release as `unknown` with no first fix. For an unlisted tag, a Composer constraint, or a modified or distributor build, report patch status as `unknown` and obtain a current release or backport record. [Packagist release index](https://repo.packagist.org/p2/livewire/livewire.json)

## Check Drupal core and its active database

For CVE-2026-9082, the package and serving-core observations must identify the same unmodified, published `drupal/core` release. A Composer constraint, a `drupal/core-recommended` metapackage version or conflicting serving evidence leaves the package verdict unknown. The bundled stable release list covers Drupal 8 through 11 and was checked on 20 November 2026. The CNA explicitly marks versions outside its six affected intervals unaffected. An unlisted version or prerelease requires separate evidence. [Packagist release index](https://repo.packagist.org/p2/drupal/core.json) · [Drupal CNA record](https://www.cve.org/CVERecord?id=CVE-2026-9082)

The publisher provides best-effort manual patches for Drupal 8.9 and Drupal 9 using the 9.5 patch. For an unmodified affected 8.x or 9.x release, report an empty first fix. For a manually patched or distributor build, record the origin and obtain the applied-patch evidence. On Drupal 10.0 through 10.4 the bulletin directs sites to 10.4.10, and on 11.0 and 11.1 it directs them to 11.1.10. [Drupal bulletin](https://www.drupal.org/sa-core-2026-004)

The example identifies core 10.5.9 and a verified non-PostgreSQL database. Expect `affected_version`, first fix 10.5.10 and `conditions_absent`. The separate Symfony and Twig dependency updates apply to all database configurations. [Example](examples/CVE-2026-9082.json) · [Drupal release notes](https://www.drupal.org/project/drupal/releases/10.5.10)

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

Report an `invalid_input` result as a request to correct the input. Retest against a new deployed inventory after an upgrade. Each result includes its advisory review date.
