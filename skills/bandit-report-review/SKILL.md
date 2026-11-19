---
name: bandit-report-review
description: Review a saved Bandit Python static-analysis report against an administrator's CI policy and expected files. Preserve actionable rule locations, suppressions, skipped files and incomplete coverage while keeping source and filenames local.
---

# Review Python findings from a saved Bandit run

Use a native Bandit JSON report and its CI records. An administrator can see whether Bandit reported a Python rule for an expected file and whether the run supplies enough evidence to report zero findings for the expected files and policy. Reported rules need source review before assigning client impact. [Bandit JSON format](https://bandit.readthedocs.io/en/latest/formatters/json.html)

The examples contain a native report under `report` and a recorded CI manifest under `context`. All three reports came from Bandit 1.9.4 running on small synthetic files. The [gap](examples/gap.json) contains B101 on an assertion. The [pass](examples/pass.json) covers both expected files. The [unknown](examples/unknown.json) contains a file-processing error.

```sh
python3 scripts/check.py < examples/gap.json
```

For a separately saved native report, provide the context file alongside it. A raw report alone returns the native issue count with unknown scope.

```sh
python3 scripts/check.py --context ci-context.json < bandit-report.json
```

Use a build manifest to supply `asset`, `build`, `policy` and the ordered `expected_files` list. Match the spelling used by CI, including any leading `./`. Obtain these expectations independently of the report’s metrics. The `ci` object repeats the identities of the actual run and records its reference. Set `policy_verified` when the job used the intended Bandit configuration and rule set, `unfiltered_output` when it retained every severity and confidence level, and `baseline_applied` from the run configuration. Set `run_completed` only for a completed analysis. Bandit’s JSON formatter filters its rows according to the run configuration. [Formatter source](https://github.com/PyCQA/bandit/blob/1.9.4/bandit/formatters/json.py) · [Bandit configuration](https://bandit.readthedocs.io/en/latest/config.html)

At CI artifact capture, record the following digest as `ci.report_digest` alongside the run metadata. The digest uses sorted JSON keys and compact separators, so an equivalent whitespace change preserves the match. It associates a report with the trusted CI record. The reader does not authenticate the CI system.

```sh
python3 scripts/check.py --digest < bandit-report.json
```

| Result | How to report it |
| --- | --- |
| `gap` | Cite the rule, severity, confidence, line and numbered expected file. A rule match is a static-analysis finding. Pair it with the independent `coverage` field. |
| `pass` | Bandit reported zero findings for the expected files under the verified policy. Each file had analyzed lines, zero suppressions, and metrics that matched the finding rows. The report recorded zero processing errors. |
| `unknown` | Identify the missing or conflicting evidence. An empty file list, processing errors, skipped tests, absent metrics, filtered results, or an unverified CI context can prevent a complete result. |

Map `file_index` back to `expected_files` locally, counting from one. The summary omits source snippets, filenames, free-text error messages, and CI identifiers. A processing error anywhere in the report leaves coverage incomplete even when another expected file has a recorded finding. An older formatter that omits the suppression counters also leaves coverage incomplete. Bandit’s code records `nosec`, `skipped_tests`, and lines of code per file. [Metrics source](https://github.com/PyCQA/bandit/blob/1.9.4/bandit/core/metrics.py)
