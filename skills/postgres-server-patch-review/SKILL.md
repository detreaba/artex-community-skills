---
name: postgres-server-patch-review
description: Compare a connected PostgreSQL backend's recorded server_version and server_version_num with four November 2026 core-server advisories, including major-specific exclusions.
---

# Check the PostgreSQL backend behind a website

Use a saved observation from the named primary or replica. Record `server_version` and `server_version_num` from the same backend session or administrator's monitoring export. For example, PostgreSQL 16.16 reports 160016. Both a JSON integer and a canonical decimal string are accepted for the numeric value. A `psql` or libpq client version identifies different software. [PostgreSQL version fields](https://www.postgresql.org/docs/current/runtime-config-preset.html) · [Server version numbering](https://www.postgresql.org/docs/current/libpq-status.html#LIBPQ-PQSERVERVERSION)

Start with the [affected backend](examples/gap.json), [fixed backend](examples/pass.json), and [conflicting server records](examples/unknown.json). Repeat the protected asset and build aliases inside `evidence`, supply a record reference, and set `source` to `connected_server` for a backend observation.

```sh
python3 scripts/check.py < examples/gap.json
```

| November 12 advisory | Reviewed affected majors | First fixed releases on those majors |
| --- | --- | --- |
| [CVE-2026-116316, restricted operations](https://www.postgresql.org/support/security/CVE-2026-116316/) | 14–18 | 14.25, 15.20, 16.16, 17.12, 18.7 |
| [CVE-2026-120145, logical replication](https://www.postgresql.org/support/security/CVE-2026-120145/) | 14–18 | 14.25, 15.20, 16.16, 17.12, 18.7 |
| [CVE-2026-116310, COPY error reporting](https://www.postgresql.org/support/security/CVE-2026-116310/) | 17–18 | 17.12, 18.7 |
| [CVE-2026-116328, memory context handling](https://www.postgresql.org/support/security/CVE-2026-116328/) | 16–18 | 16.16, 17.12, 18.7 |

This edition reviews majors 14 through 18. Within them, report `outside_affected_range` when the publisher explicitly excludes an older major for that advisory. Other majors, conflicting observations, prereleases, and distributor or managed-service backports return `unknown`. Even where the upstream fix is present, support lifecycle is a separate decision. [PostgreSQL November release](https://www.postgresql.org/about/news/postgresql-187-1712-1616-1520-1425-and-19-rc-2-released-3442/)

For the client, identify the specific backend, build, version, advisory and evidence reference. Repeat the review for other replicas or pool members that serve the application. The upstream version verdict establishes neither use of an affected feature nor application exposure.
