---
name: nessus-credentialed-coverage
description: Interpret a saved Nessus v2 report to determine whether plugin 19506 recorded credentialed OS checks for one host in one identified run.
---

# Review a host's Nessus credentialed-check evidence

Use this skill when an administrator wants to know whether existing Nessus results include affirmative evidence of credentialed OS checks. On Linux, UNIX and macOS, Tenable requires access to the native package or patch inventory for an affirmative result. Windows has registry and system-access requirements. An accepted login alone leaves OS check coverage open. [Tenable credentialed checks](https://docs.tenable.com/nessus/Content/NessusCredentialedChecks.htm) · [Scan information plugin 19506](https://www.tenable.com/plugins/nessus/19506)

## Use a saved report

Run the checker locally with Python 3.9 or later. This example contains a negative scan-information flag alongside a successful login.

```sh
python3 scripts/check.py < examples/gap.json
```

For an owner's report, copy the example and remove `xml`. Supply short, redacted aliases for the asset, scan run and evidence reference in `asset`, `run` and `ref`. Select the report, host and run by copying the exact `Report/@name`, `ReportHost/@name` and `HostProperties/tag[@name='HOST_START']` text to `report_name`, `host_name` and `host_start`. A recurring scan can reuse a report and host name. [Nessus v2 file format](https://static.tenable.com/documentation/nessus_v2_file_format.pdf)

Set `direct_os_scan_verified` to true when the owner's run record ties this observation to a direct assessment of that general-purpose OS host. Leave it false or omit it for uncertain provenance, network devices, management APIs or agent inventory. Those sources use different credentialing semantics. For example, a VMware management integration can populate the same flag using its own inventory. [Tenable network and API semantics](https://docs.tenable.com/nessus/Content/credentialed-checks-on-network-devices-and-apis.htm) · [VMware integration results](https://docs.tenable.com/integrations/VMware/Content/scan-results-review.htm)

```sh
python3 scripts/check.py --xml-file saved-report.nessus < scope.json
```

Supply a local XML file up to 8 MiB, or embed its text in `xml` as in the examples. For a larger report, use a redacted v2 excerpt with the original report and host nesting, host start time, every plugin 19506 item and its complete output, and any host items for 21745 or 110695. Set `coverage_records_complete` to true when the export retained these items together for the selected host. A filtered export with uncertain coverage leaves the decision open. The scan policy, authentication details and unrelated findings can be removed. Keep the raw export local. Paste the checker's projected result into ARTEX.

## Explain the outcome

- `reported_yes` means the selected OS host's scan-information record explicitly reports yes. The reader recognizes the bare value and SSH or SMB method suffixes. Report the asset, run and evidence reference. Individual plugin coverage and the host's patch status require separate evidence. [Affirmative fixture](examples/pass.json)
- `reported_no` means the selected host's scan-information record explicitly reports no. Request the owner's authentication or inventory-access records if the reason matters. [Negative fixture](examples/gap.json)
- `unknown` covers absent, ambiguous, contradictory or truncated evidence, an unsupported method, or a host/run mismatch. A recorded login without the scan-information flag leaves the decision open. An affirmative flag alongside a host result declaring OS patch assessment unavailable also needs reconciliation. [Login-only fixture](examples/unknown.json) · [Plugin 21745](https://www.tenable.com/plugins/nessus/21745) · [Plugin 110695](https://www.tenable.com/plugins/nessus/110695) · [Tenable export truncation](https://developer.tenable.com/reference/scans-export-request)

For `invalid_input`, ask for corrected scope JSON or Nessus v2 XML. The checker accepts regular XML without a document type declaration.
