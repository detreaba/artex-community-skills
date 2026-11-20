---
name: tomcat-patch-review
description: Check Apache Tomcat patch status for CVE-2026-103119, CVE-2025-24813 and CVE-2026-34486 using saved evidence of the defining artifact loaded in one serving JVM.
---

# Review the Tomcat release loaded by a serving JVM

Use the administrator’s checker result to report the patch level of one Tomcat instance. Select the advisory in the input and identify the class changed by its fix.

## Connector output buffer

For CVE-2026-103119, identify `org.apache.catalina.connector.OutputBuffer` in Catalina or embedded core. Apache published CVE-2026-103119 on 20 October 2026. Its bulletin says “Affects: 11.0.0-M25 to 11.0.26” and places the fix in 11.0.27. This checker covers stable 11.0 artifacts in Apache's release archive through 19 November 2026. Apache skipped 11.0.28. The next published release after the fix was 11.0.29. [Apache bulletin](https://tomcat.apache.org/security-11.html#Fixed_in_Apache_Tomcat_11.0.27) · [Release archive](https://archive.apache.org/dist/tomcat/tomcat-11/)

## Default servlet

For CVE-2025-24813, identify `org.apache.catalina.servlets.DefaultServlet` in Catalina or embedded core. Apache published the advisory on 10 March 2025. Its CNA record also covers the retired 8.5 line. [Apache CNA record](https://www.cve.org/CVERecord?id=CVE-2025-24813) · [Apache 9](https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.99) · [Apache 10](https://tomcat.apache.org/security-10.html#Fixed_in_Apache_Tomcat_10.1.35) · [Apache 11](https://tomcat.apache.org/security-11.html#Fixed_in_Apache_Tomcat_11.0.3)

| Line | Published stable affected releases | First fixed |
| --- | --- | --- |
| 8.5 | 8.5.3 through 8.5.100 | None on this retired line |
| 9.0 | 9.0.4 through 9.0.98 | 9.0.99 |
| 10.1 | 10.1.0 through 10.1.34 | 10.1.35 |
| 11.0 | 11.0.0 through 11.0.2 | 11.0.3 |

Only published stable artifacts through 20 November 2026 are covered. Skipped patch numbers and the 10.0 line yield `unknown`. Apache’s ranges include early milestones and the numeric betas 8.5.0, 8.5.2, 9.0.1 and 9.0.2. These releases require prerelease-specific review. [Apache archive](https://archive.apache.org/dist/tomcat/) · [2016 announcements](https://tomcat.apache.org/oldnews-2016.html) · [2017 announcements](https://tomcat.apache.org/oldnews-2017.html)

## Tribes clustering interceptor

For CVE-2026-34486, identify `org.apache.catalina.tribes.group.interceptors.EncryptInterceptor` in the serving JVM. Its defining artifact is Tomcat Tribes, with the modern bundle name `org.apache.tomcat-tribes` and Maven coordinate `org.apache.tomcat:tomcat-tribes:VERSION`. A loaded Catalina, embedded-core or enclosing application version leaves the Tribes release unresolved. Apache published this advisory on 9 April 2026. [Apache CNA record](https://www.cve.org/CVERecord?id=CVE-2026-34486) · [Apache 9](https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.117) · [Apache 10](https://tomcat.apache.org/security-10.html#Fixed_in_Apache_Tomcat_10.1.54) · [Apache 11](https://tomcat.apache.org/security-11.html#Fixed_in_Apache_Tomcat_11.0.21) · [Published Tribes artifacts](https://repo.maven.apache.org/maven2/org/apache/tomcat/tomcat-tribes/)

| Branch | Only affected release | First fixed |
| --- | --- | --- |
| 9.0 | 9.0.116 | 9.0.117 |
| 10.1 | 10.1.53 | 10.1.54 |
| 11.0 | 11.0.20 | 11.0.21 |

Earlier reviewed stable releases that contain the class give `outside_affected_range` with a null first fix. On 9.0 the first published artifact containing this class was 9.0.13. A legacy Tribes artifact with a missing or shared bundle name must match its own published Maven digest and coordinate before the checker reports an earlier release outside the affected range. An inventory claiming to have loaded it from an earlier 9.0 release yields `unknown`. Published stable releases at or after the fix on each reviewed line give `vendor_fix_present`. The class inventory does not establish clustering configuration. [Affected Tribes example](examples/CVE-2026-34486.json)

A Tribes verdict applies only to CVE-2026-34486. For example, 9.0.115 predates this regression and falls in Apache’s affected range for CVE-2026-29146. Release 9.0.117 includes this regression’s fix and falls in the affected range for CVE-2026-95517. Review the deployed release separately against each applicable EncryptInterceptor advisory. Apache lists the following affected ranges on the three supported lines. [Apache Tomcat 9](https://tomcat.apache.org/security-9.html) · [Apache Tomcat 10](https://tomcat.apache.org/security-10.html) · [Apache Tomcat 11](https://tomcat.apache.org/security-11.html)

| Other EncryptInterceptor advisory | Tomcat 9 | Tomcat 10 | Tomcat 11 |
| --- | --- | --- | --- |
| CVE-2026-29146 | 9.0.13–9.0.115 | 10.0.0-M1–10.1.52 | 11.0.0-M1–11.0.18 |
| CVE-2026-55955 | 9.0.13–9.0.118 | 10.1.0-M1–10.1.55 | 11.0.0-M1–11.0.22 |
| CVE-2026-59084 | 9.0.13–9.0.119 | 10.1.0-M1–10.1.56 | 11.0.0-M1–11.0.23 |
| CVE-2026-95517 | 9.0.13–9.0.123 | 10.1.0-M1–10.1.61 | 11.0.0-M1–11.0.27 |

## Identify the loaded artifact

Use a saved owner inventory from the serving JVM. Enter short, redacted aliases for the `asset`, deployed `build`, specific running `instance` and evidence `ref`. Use a per-start instance reference so an earlier JVM cannot stand in for a replacement.

1. Identify the defining artifact of the advisory’s class in the serving container’s class loader. A class-load record can identify the class's code source. Set `source` to `serving_class_manifest` and `deployment_verified` to true only when the record ties that class and the exact artifact bytes to this running instance. A file at the same path after an upgrade can contain different bytes. [Java code source](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/CodeSource.html#getLocation()) · [Tomcat class loaders](https://tomcat.apache.org/tomcat-11.0-doc/class-loader-howto.html)
2. Copy `Bundle-SymbolicName` and `Implementation-Version` from that JAR's main manifest into `bundle_symbolic_name` and `implementation_version`. In modern releases, the standard `catalina.jar` identifies itself as `org.apache.tomcat-catalina`. Embedded core identifies itself as `org.apache.tomcat-embed-core`. For a nested JAR, read the manifest of the identified nested artifact. The enclosing application has its own version. [Catalina bundle](https://github.com/apache/tomcat/blob/11.0.27/res/bnd/catalina.jar.tmp.bnd) · [Embedded core bundle](https://github.com/apache/tomcat/blob/11.0.27/res/bnd/tomcat-embed-core.jar.tmp.bnd) · [Manifest version](https://github.com/apache/tomcat/blob/11.0.27/res/bnd/build-defaults.bnd)
3. Set `origin` to `upstream` when provenance independently ties those bytes to an Apache release, for example through a recorded digest match. Enter that release in `upstream_version`. A Maven build file, a server banner, a management version string, or a JAR found on disk alone leaves the runtime decision open.

### Manifests with a missing or shared bundle name

Older releases, including all of 8.5, and releases 9.0.91 and 10.1.26 can lack an artifact-specific bundle name. Some early 9.0 JARs share a name such as `TOMCAT_9_0_13`. Preserve that exact header when present and omit it when absent. For these releases, also supply `inventory.maven_provenance`.

Use a separate `ref` for an independent artifact comparison and the full Maven `coordinate`, including version. Record the hexadecimal SHA-256 of the actual loaded JAR in `loaded_sha256` and the SHA-256 independently obtained from the published JAR in `published_sha256`. Coordinates for the default servlet are `org.apache.tomcat:tomcat-catalina:VERSION` and `org.apache.tomcat.embed:tomcat-embed-core:VERSION`. For a missing or shared bundle name, the checker also requires the digest and full coordinate to match the bundled catalog of exact Maven Central JAR bytes. Keep `scripts/legacy-artifacts.sha256` beside the checker. The running JVM’s class and loaded bytes still depend on the owner’s inventory. If the inventory includes this comparison with a modern bundle name, both must identify the same artifact. [8.5 example](examples/CVE-2025-24813.json) · [Published Catalina artifacts](https://repo.maven.apache.org/maven2/org/apache/tomcat/tomcat-catalina/) · [Published embedded artifacts](https://repo.maven.apache.org/maven2/org/apache/tomcat/embed/tomcat-embed-core/)

## Run and interpret

From the unpacked skill directory, run the offline checker with Python 3.9 or later. Substitute the operator's inventory for the synthetic example when reviewing a deployment.

```sh
python3 scripts/check.py < examples/gap.json
```

In ARTEX, ask for the checker JSON and its evidence reference. Cite the advisory, asset, build, instance and evidence reference in the answer.

- `affected_version` identifies a loaded upstream release inside the published range. Give `first_fixed_on_branch` when present. For affected 8.5, report that Apache provides no fix on that line. Request a new class inventory after updating and restarting. [Affected standalone example](examples/gap.json)
- `vendor_fix_present` confirms the fix in the identified artifact. Other JVMs in a rolling deployment need their own observations. [Fixed embedded example](examples/pass.json)
- `outside_affected_range` identifies a verified Tribes release predating its branch’s regression. Report the observed version and leave the first fix empty.
- `unknown` identifies missing or conflicting evidence, another release line, or a release outside this review. Milestones, including the affected M25 named by Apache, require separate review. A distributor build needs its distributor's patch decision. Use `patch_reason` to identify the missing evidence. [Build-file-only example](examples/unknown.json)

Keep `applicability` unknown. A release inventory cannot establish runtime configuration, site exposure or impact. An `invalid_input` result calls for a corrected JSON record.
