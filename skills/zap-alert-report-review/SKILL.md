---
name: zap-alert-report-review
description: Triage an owner's saved OWASP ZAP Traditional JSON alert export against an explicit risk and confidence threshold for one website origin and build. Report matched rule IDs and counts with sensitive report content omitted.
---

# Triage a saved ZAP report

Use this skill to answer whether the owner's saved report contains alerts that meet the team's review threshold. It reads one existing ZAP Traditional JSON export with Python 3.9 or newer. The operator keeps the full report locally and supplies ARTEX with the checker's JSON output. [ZAP report format](https://www.zaproxy.org/docs/desktop/addons/report-generation/report-traditional-json/)

Try the [qualifying alert](examples/gap.json), [below-threshold alert](examples/pass.json), and [empty export](examples/unknown.json) examples.

```sh
python3 scripts/check.py < examples/gap.json
```

## Supply a client export

1. Set the same opaque asset and build aliases in `policy` and `evidence`. Supply a policy reference and a report reference. Set `policy.origin` to the site’s scheme, host and optional port. The checker verifies these against the site's native report fields and each retained instance URI.
2. Set the policy's minimum risk to `informational`, `low`, `medium` or `high`. Set its minimum confidence to `low`, `medium`, `high` or `user_confirmed`. An alert must meet both minimums. A false-positive label places it below the threshold. ZAP permits manual and filter-based changes to confidence. [ZAP alert fields](https://www.zaproxy.org/docs/desktop/start/features/alerts/) · [Numeric ratings](https://github.com/zaproxy/zaproxy/blob/main/zap/src/main/java/org/parosproxy/paros/core/scanner/Alert.java)
3. Set `evidence.run_status` to `completed` when the recorded run completed successfully. Set `evidence.export_scope` to `all_recorded_alerts` when the owner verified that the export includes all stored alerts for this origin. Use `unknown` for an uncertain or filtered export.
4. Omit `evidence.document` from the JSON envelope when providing a separate export. The size limit is four MiB per JSON file.

```sh
python3 scripts/check.py --report-file saved-zap-report.json < review-policy.json
```

## Read the result

- `gap` means at least one recorded alert group meets the owner's triage threshold. Quote the rule ID, reported risk, confidence and instance count when recording the review item.
- `pass` means all retained groups in a nonempty, fully exported report fall below this specific threshold. The website's overall security, path coverage and exploitability remain unknown.
- `unknown` covers empty reports, an uncertain run, ambiguous site identity, conflicting instance counts and incomplete exports without a qualifying group. A valid qualifying alert can still be reported with `export_coverage=partial` when other groups lack usable evidence.

The checker counts entries in the saved export. Repeated instances can represent the same underlying issue. Each result retains `site_exposure=unknown`, including when the recorded confidence is `user_confirmed`. The output includes only owner aliases, structured rule identifiers, normalized ratings, counts and verdicts. It omits report URLs, parameters, names, descriptions, request/response contents and observed values. [ZAP template](https://github.com/zaproxy/zap-extensions/blob/main/addOns/reports/src/main/zapHomeFiles/reports/traditional-json/report.json) · [Upstream sample](https://github.com/zaproxy/zap-extensions/blob/main/addOns/reports/src/test/resources/org/zaproxy/addon/reports/resources/basic-traditional-json.json)
