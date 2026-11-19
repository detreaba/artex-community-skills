---
name: mysql-loadable-function-review
description: Compare a saved Oracle MySQL 8.4 Performance Schema loadable-function inventory with the approved registrations for one server instance and build.
---

# Review registered MySQL loadable functions

Use this skill to answer whether the registrations recorded on a particular running MySQL 8.4 server satisfy the owner's allowlist. Performance Schema records both explicitly registered library functions and functions registered by a component or plugin. The system table `mysql.func` covers only the former. [Oracle Performance Schema reference](https://dev.mysql.com/doc/refman/8.4/en/performance-schema-user-defined-functions-table.html) · [MySQL system schema](https://dev.mysql.com/doc/refman/8.4/en/system-schema.html)

Run the offline reader with Python 3.9 or later. The sample contains one approved aggregate and one unapproved name in a partial export.

```sh
python3 scripts/check.py < examples/gap.json
```

## Prepare the policy and saved export

Use opaque `instance`, `build` and `ref` aliases for the applicable policy and evidence. Use the same instance and build aliases in both records. Set `policy.reviewed` to true when its `allow` list contains the owner's complete approved alternatives for this deployment. An allowlist permits entries to exist. It imposes no requirement to install every permitted entry.

- Each approved entry specifies a function `name`, `type` (`function` or `aggregate`), and `library`. A filename approves an explicit library registration with that exact spelling. JSON `null` approves automatic registration by a component or plugin. List both entries if both registration classes are allowed. If an automatic registration requires a particular component or plugin, add its alias as `provider`. This inventory cannot identify that individual provider.
- In `evidence`, supply the saved server release, `product: "mysql"`, `origin: "upstream"`, and `server_verified: true` when the record identifies the running Oracle MySQL instance. Use its stable upstream 8.4.x release, the source `performance_schema.user_defined_functions`, a snapshot alias and the actual ordered `rows` from the export. A client version, a fork or an unidentified downstream build leaves the answer open.
- Preserve the native `UDF_NAME`, `UDF_TYPE` and `UDF_LIBRARY` fields. Keep a SQL NULL as JSON `null`. Redacted or omitted columns and textual null placeholders leave that field unresolved. Usage count and return type do not decide this registration policy. [MySQL 8.4 row projection](https://github.com/mysql/mysql-server/blob/8a180268d832300c09a375115dfa0ea77d83f1af/storage/perfschema/table_user_defined_functions.cc#L275-L296)
- Set `coverage` to `complete` only for a successful unfiltered export of all registrations. Include `total.unfiltered_rows` from an independently recorded count for that same snapshot, its `snapshot` alias and a `ref` for the count. A returned page length cannot supply this count. Use `partial` for a filter, truncation or uncertain coverage. An identified extra registration still warrants review.

The reader compares portable ASCII function names case-insensitively. A duplicate name makes both rows ambiguous, including rows that report different types. For libraries it compares the registered filename spelling. List each spelling the owner permits. Unsupported names, paths and unidentifiable providers need a separate manual check. The input limit is 4 MiB and 10,000 rows per list. [Table primary key](https://github.com/mysql/mysql-server/blob/8a180268d832300c09a375115dfa0ea77d83f1af/storage/perfschema/table_user_defined_functions.cc#L43-L53) · [Server registration name lookup](https://github.com/mysql/mysql-server/blob/8a180268d832300c09a375115dfa0ea77d83f1af/sql/sql_udf.cc#L205-L213)

## Interpret the result

| Status | What the operator can report |
| --- | --- |
| `gap` | At least one identified registration falls outside the policy. Use the one-based positions and reasons in `gaps` to locate the rows in the saved export. Report any `unresolved` rows alongside them. [Partial export with an extra registration](examples/gap.json) |
| `pass` | Every row in the complete, count-checked snapshot satisfies an approved entry. A verified empty inventory also satisfies an allowlist. [Complete matching inventory](examples/pass.json) |
| `unknown` | The available evidence cannot settle the policy. A null library identifies the registration class. To attribute it to a specific provider, obtain separate, same-instance evidence linking that function to that provider. [Provider identity unresolved](examples/unknown.json) |

Paste the result into ARTEX with the policy and evidence references. The checker returns row positions and reason codes so raw registered names and filenames can stay local. Registration metadata alone cannot establish library contents or integrity, invocation, compromise, or patch status. For `invalid_input` (exit 2), correct the JSON structure or policy fields.
