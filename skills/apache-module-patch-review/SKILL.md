---
name: apache-module-patch-review
description: Review the provenance and release of a serving Apache HTTP Server module for the November 2026 mod_http2, mod_md and mod_vhost_alias advisories, including separate upstream mod_h2 builds.
---

# Check the module used by an Apache instance

Use a saved record tying the relevant module artifact to the serving instance. Record its provenance and the observed server version. A package manifest for a different image or a server response header leaves the module release unknown.

The [gap example](examples/gap.json) describes an Apache 2.4.71 server loading a separate upstream mod_h2 2.0.42 artifact. Compare it with the [fixed bundled module](examples/pass.json) and the [banner-only record](examples/unknown.json).

```sh
python3 scripts/check.py < examples/gap.json
```

Use matching asset and build aliases and an opaque evidence reference. Set `source` to `serving_module_inventory` when the inventory identifies which artifact the instance uses. For `module_origin=httpd-bundle`, supply the httpd release that provided that module in `module_release`. A conclusive bundled verdict requires this to match `server_version`. For `module_origin=standalone-mod_h2`, supply the standalone release in `module_release`.

| Advisory | Module | Affected bundled httpd releases | First bundled fix |
| --- | --- | --- | --- |
| CVE-2026-119618 | mod_http2 | 2.4.55 through 2.4.70 | 2.4.71 |
| CVE-2026-106023 | mod_md | 2.4.30 through 2.4.70 | 2.4.71 |
| CVE-2026-109163 | mod_vhost_alias | 2.4.69 through 2.4.70 | 2.4.71 |

Apache also identifies standalone mod_h2 2.0.8 through 2.0.42 as affected by CVE-2026-119618. The checker reports the affected standalone release and leaves the fixed version blank. A candidate standalone upgrade needs its own published fix evidence. [Apache security bulletin](https://httpd.apache.org/security/vulnerabilities_24.html#2.4.71) · [Standalone release history](https://github.com/icing/mod_h2/releases)

In a client report, identify the module, its upstream source, the asset, build and evidence reference. Use `unknown` for incomplete or conflicting provenance and for distribution packages requiring a separate backport decision. `outside_affected_range` describes an earlier upstream bundled release. Each result concerns the recorded module. Site configuration and exposure require separate evidence.
