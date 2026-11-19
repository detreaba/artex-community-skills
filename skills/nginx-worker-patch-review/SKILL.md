---
name: nginx-worker-patch-review
description: Review an NGINX Open Source worker's recorded release against ten November 2026 upstream advisories, including stable and mainline branch differences and mixed worker generations during upgrades.
---

# Check the release of an NGINX worker

Use an owner's saved deployment inventory for one serving worker. Record the upstream release of that worker's executable as `worker_version` and set `source` to `running_worker`. An installed package version can be recorded separately in `installed_version`. During a binary upgrade both old and new worker generations can accept requests. Identify which worker each observation describes. [NGINX process control](https://nginx.org/en/docs/control.html)

Start with the [mixed-generation example](examples/gap.json). Replace the asset, build, advisory and evidence reference with the operator's own values. Repeat the same asset and build inside `evidence`. The public checker reads one JSON record from standard input.

```sh
python3 scripts/check.py < examples/gap.json
```

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

For a client report, cite the advisory, asset, build, worker version and evidence reference. `affected_version` identifies an upstream release in a vendor range. `vendor_fix_present` identifies the upstream branch fix. `outside_affected_range` describes a release before the vendor's stated introduction. When the record comes from a banner or installed package alone, concerns another build, or identifies NGINX Plus or a distribution backport, report `unknown`. The [fixed](examples/pass.json) and [package-only](examples/unknown.json) examples illustrate the distinction.

Feature enablement and site exposure remain unknown in this comparison. Inventory other serving workers before drawing conclusions about an entire deployment.
