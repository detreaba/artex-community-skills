---
name: greenbone-result-override-review
description: Review whether an override changed the displayed severity of one result in a saved Greenbone GMP 22.7 XML report. Retain the result's recorded quality of detection and the export's filter settings.
---

# Review a Greenbone result override

Use this skill when an operator sees a severity change in a saved report and needs to explain it. A Greenbone override changes how a finding appears. Keep remediation status open until separate evidence establishes what changed on the host. [Greenbone report and override guide](https://docs.greenbone.net/GSM-Manual/gos-22.04/en/reports.html#using-overrides-and-false-positives)

## Select one recorded result

Use Python 3.9 or later. The packaged example shows a recorded 8.0 displayed as 0.0 after an override, with a result QoD of 80 and an export minimum of 70. [Synthetic changed result](examples/gap.json)

```sh
python3 scripts/check.py < examples/gap.json
```

For an existing report, supply its XML locally. Copy the example envelope, remove `xml` and set the following fields. An inline XML excerpt and a separate file use the same reader.

| Field | What to supply |
| --- | --- |
| `asset`, `ref` | Short redacted aliases for the asset and this specific saved observation. Keep the mapping from the reference to the report and selected result locally. |
| `report_id`, `result_id` | Report and result UUIDs from the owner's record. The outer and inner report UUIDs must agree when both are present. |
| `host`, `nvt_oid` | The direct text of the result's `host` and its `nvt/@oid`. These identify the row together with the two UUIDs. |

```sh
python3 scripts/check.py --xml-file saved-report.xml < selection.json
```

The reader accepts the inner scan report, the wrapped XML report, or a successful saved `get_reports_response`. The XML limit is 8 MiB. For a larger export, preserve the original report nesting, version, filters, selected result and all its associated overrides. Keep any duplicate rows with the same result UUID so ambiguity stays visible. Retain the owner’s local copy of the original. The publisher's XML example shows the report and result paths. It omits the severity pair and QoD, so its result stays `unknown`. [Native GMP report example](https://docs.greenbone.net/API/GMP/gmp-22.7.html#command_get_reports) · [GMP result fields](https://docs.greenbone.net/API/GMP/gmp-22.7.html#element_result)

## Interpret the output

| Status | Operator decision |
| --- | --- |
| `gap` | Review the recorded override. The report applied overrides, the two scores differ and one active, scoped override records the displayed replacement. Quote the direction, both scores, result QoD and evidence reference. |
| `pass` | The original and displayed scores are numerically equal for this result. This can occur even with an override present. [Equal-score example](examples/pass.json) |
| `unknown` | Explain which evidence is missing or inconsistent using `reason`. An absent original score or a filtered-out result leaves the comparison open. An observed numeric change can survive even when its cause is uncertain. [Missing-original example](examples/unknown.json) |

For a positive original severity, the reader checks that the saved VT base score equals the recorded original. Greenbone's dynamic severity setting can otherwise change the display following a VT update. For a changed result, retain detailed override fields including the scope, active and orphan flags, original-score constraint and replacement. Empty native scope fields represent unrestricted scope. The checker can match explicit host addresses, a matching port and task, and an individual or unrestricted result. Abbreviated override records, unresolved host ranges, multiple candidate rules and delta reports leave attribution open. It compares ordinary scores and the `-1` false-positive score. Other special severity codes leave the comparison open. [Dynamic severity setting](https://docs.greenbone.net/GSM-Manual/gos-24.10/en/web-interface.html) · [Manager severity calculation](https://github.com/greenbone/gvmd/blob/4a64eda7bffddd4048ff707c7687bc54ca30859a/src/manage_sql.c#L20906-L20969) · [GMP override fields](https://docs.greenbone.net/API/GMP/gmp-22.7.html#element_override)

Read `qod` as the result's recorded detection quality. `filters.min_qod` is the export threshold. `filters.apply_overrides` records whether the export applied overrides, and `filters.overrides` records whether it included their descriptions. The output retains recognized level filters and a SHA-256 digest of the filter term for comparison with the local report. Raw host identifiers, filter text, notes and descriptions stay in the source file. Paste the checker's JSON projection into ARTEX. For `invalid_input` (exit 2), check the envelope and XML format. [Quality of detection](https://docs.greenbone.net/GSM-Manual/gos-22.04/en/reports.html#quality-of-detection-concept) · [Native filter representation](https://github.com/greenbone/gvmd/blob/4a64eda7bffddd4048ff707c7687bc54ca30859a/src/gmp_get.c#L488-L544)
