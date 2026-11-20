---
name: nginx-worker-patch-review
description: Review one running NGINX worker against the May 2026 rewrite advisory for Open Source and Plus or ten November Open Source advisories.
---

# Check the release of an NGINX worker

Use an owner's saved deployment inventory for one serving worker. Record the upstream release of that worker's executable as `worker_version` and set `source` to `running_worker`. An installed package version can be recorded separately in `installed_version`. During a binary upgrade both old and new worker generations can accept requests. Identify which worker each observation describes. [NGINX process control](https://nginx.org/en/docs/control.html)

Start with the [mixed-generation example](examples/gap.json). Replace the asset, build, advisory and evidence reference with the operator's own values. Repeat the same asset and build inside `evidence`. The public checker reads one JSON record from standard input.

```sh
python3 scripts/check.py < examples/gap.json
```

## May rewrite advisory

For CVE-2026-42945, use `product: "nginx-oss"` or `product: "nginx-plus"`. Set `evidence.worker` to a redacted generation alias and `deployment_verified` to true when the process record identifies this serving worker’s executable. Supply its SHA-256 in `worker_sha256`. During an in-place upgrade, use the backing file object for that running process. Reopening the current installation pathname can select the replacement. [Plus rollout example](examples/CVE-2026-42945.json) · [NGINX binary upgrades](https://nginx.org/en/docs/control.html)

In `release_provenance`, provide a separate `ref`, the upstream `product`, its exact `version` and `executable_sha256`. Set `verified` to true when your evidence authenticates the release and ties that digest to the executable inside the publisher’s package, or to a reproducible unmodified upstream build. Both hashes describe the executable. A package archive has its own digest. The checker compares saved values and relies on the operator for their provenance. A distribution backport requires a distributor decision.

| Running product and release | Patch decision |
| --- | --- |
| Open Source | Published 0.6.27 through 1.30.0 are affected. Earlier published releases are outside the range. The stable fix is 1.30.1 and the mainline fix is 1.31.0. Older affected branches have a null `first_fixed_on_branch`. |
| Plus R32 and R36 | Give the exact F5 base release or patch label, such as `R32`, `R32 P6` or `R36 P4`. Use the base label only for the initial release confirmed by the upstream evidence. R32 P6 and R36 P4 are the respective first fixes. |
| Plus 37 | Supply the full published LTS or CR build, for example `PLS.37.0.0.1` or `PLS.37.1.1.2`. F5 designates the series unaffected. The result is `outside_affected_range` with a null first fix. |

The review covers releases in the public catalogs on 20 November 2026. Unpublished labels, Plus R33–R35, a bare `R37`, a core version offered as a Plus patch, and a mismatch between provenance and the running bytes yield `unknown`. Cite the running worker and both evidence references. The result concerns this advisory and this worker. Module use, configuration and exposure require separate evidence. [Upstream security index](https://nginx.org/en/security_advisories.html) · [Open Source releases](https://nginx.org/download/) · [F5 advisory](https://my.f5.com/manage/s/article/K000161019) · [F5 CNA record](https://www.cve.org/CVERecord?id=CVE-2026-42945) · [Plus release notes](https://docs.nginx.com/nginx/releases/)

When reporting a conclusive May result, retain the provenance statement in `patch_reason`. The operator supplies the independent evidence that the reference digest belongs to the authenticated release executable. Matching the two supplied hashes alone cannot distinguish an authentic comparison from a copied value. A different, unrecognized installed release warrants reconciliation with the worker inventory. The verdict describes the named running generation.

## November Open Source advisories

| November 18 advisory | Feature | Earliest affected upstream release |
| --- | --- | --- |
| CVE-2026-123634 | Resolver | 0.6.18 |
| CVE-2026-123007 | HTTP/2 flow control | 1.9.5 |
| CVE-2026-121810 | HTTP/3 | 1.25.0 |
| CVE-2026-123633 | HTTP/2 | 1.19.7 |
| CVE-2026-118899 | TLS 1.3 request bodies | 1.13.0 |
| CVE-2026-113425 | Mail proxy | 0.5.33 |
| CVE-2026-120993 | PROXY protocol v2 | 1.31.4 |
| CVE-2026-125283 | URI-to-file mapping | 0.9.6 |
| CVE-2026-120967 | Stream client certificate checks | 1.25.5 |
| CVE-2026-123640 | Stream TLS preread | 1.15.2 |

The nine advisories affecting both branches have fixes in 1.30.7 and 1.31.9. CVE-2026-120993 concerns 1.31.4 through 1.31.8 only. For example, 1.30.6 is outside that advisory and affected by CVE-2026-123007. Older affected branches with no listed fix on that branch have an empty `first_fixed_on_branch`. [NGINX security index](https://nginx.org/en/security_advisories.html) · [Stable release notes](https://nginx.org/en/CHANGES-1.30) · [Mainline release notes](https://nginx.org/en/CHANGES)

For a client report, cite the advisory, asset, build, worker version and evidence reference. `affected_version` identifies an upstream release in a vendor range. `vendor_fix_present` identifies the upstream branch fix. `outside_affected_range` covers a release before the vendor's stated introduction or a later series the vendor explicitly designates unaffected. For example, F5 lists Plus 37 as unaffected and gives no first fix for that series. For these ten Open Source advisories, a banner, an installed package alone, another build, NGINX Plus or a distribution backport yields `unknown`. The [fixed](examples/pass.json) and [package-only](examples/unknown.json) examples illustrate the distinction.

Feature enablement and site exposure remain unknown in this comparison. Inventory other serving workers before drawing conclusions about an entire deployment.
