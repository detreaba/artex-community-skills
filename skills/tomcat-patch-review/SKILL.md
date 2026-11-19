---
name: tomcat-patch-review
description: Check whether a running Apache Tomcat instance uses the upstream fix for CVE-2026-103119. Interpret saved Catalina or embedded-core class and artifact evidence for one serving JVM.
---

# Review the Tomcat release loaded by a serving JVM

Use the administrator's checker result to report the patch level of one Tomcat instance. Apache published CVE-2026-103119 on 20 October 2026. Its bulletin says “Affects: 11.0.0-M25 to 11.0.26” and places the fix in 11.0.27. This checker covers stable 11.0 artifacts in Apache's release archive through 19 November 2026. Apache skipped 11.0.28. The next published release after the fix was 11.0.29. [Apache bulletin](https://tomcat.apache.org/security-11.html#Fixed_in_Apache_Tomcat_11.0.27) · [Release archive](https://archive.apache.org/dist/tomcat/tomcat-11/)

## Identify the loaded artifact

Use a saved owner inventory from the serving JVM. Enter short, redacted aliases for the `asset`, deployed `build`, specific running `instance` and evidence `ref`. Use a per-start instance reference so an earlier JVM cannot stand in for a replacement.

1. Identify the defining artifact of `org.apache.catalina.connector.OutputBuffer` in the serving container's class loader. A class-load record can identify the class's code source. Set `source` to `serving_class_manifest` and `deployment_verified` to true only when the record ties that class and the exact artifact bytes to this running instance. A file at the same path after an upgrade can contain different bytes. [Java code source](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/CodeSource.html#getLocation()) · [Tomcat class loaders](https://tomcat.apache.org/tomcat-11.0-doc/class-loader-howto.html)
2. Copy `Bundle-SymbolicName` and `Implementation-Version` from that JAR's main manifest into `bundle_symbolic_name` and `implementation_version`. The standard `catalina.jar` identifies itself as `org.apache.tomcat-catalina`. Embedded core identifies itself as `org.apache.tomcat-embed-core`. For a nested JAR, read the manifest of the identified nested artifact. The enclosing application has its own version. [Catalina bundle](https://github.com/apache/tomcat/blob/11.0.27/res/bnd/catalina.jar.tmp.bnd) · [Embedded core bundle](https://github.com/apache/tomcat/blob/11.0.27/res/bnd/tomcat-embed-core.jar.tmp.bnd) · [Manifest version](https://github.com/apache/tomcat/blob/11.0.27/res/bnd/build-defaults.bnd)
3. Set `origin` to `upstream` when provenance independently ties those bytes to an Apache release, for example through a recorded digest match. Enter that release in `upstream_version`. A Maven build file, a server banner, a management version string, or a JAR found on disk alone leaves the runtime decision open.

## Run and interpret

From the unpacked skill directory, run the offline checker with Python 3.9 or later. Substitute the operator's inventory for the synthetic example when reviewing a deployment.

```sh
python3 scripts/check.py < examples/gap.json
```

In ARTEX, ask for the checker JSON and its evidence reference. Cite the advisory, asset, build, instance and evidence reference in the answer.

- `affected_version` identifies a loaded upstream release inside the published range. Give the first fix and ask for a new class inventory after the update and restart. [Affected standalone example](examples/gap.json)
- `vendor_fix_present` confirms the fix in the identified artifact. Other JVMs in a rolling deployment need their own observations. [Fixed embedded example](examples/pass.json)
- `unknown` identifies missing or conflicting evidence, another release line, or a release outside this review. Milestones, including the affected M25 named by Apache, require separate review. A distributor build needs its distributor's patch decision. Use `patch_reason` to identify the missing evidence. [Build-file-only example](examples/unknown.json)

Keep `applicability` unknown. A release inventory cannot establish connector configuration, site exposure or impact. An `invalid_input` result calls for a corrected JSON record.
