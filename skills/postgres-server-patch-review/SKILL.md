---
name: postgres-server-patch-review
description: Compare a connected PostgreSQL backend's recorded server_version and server_version_num with November 2026 core-server advisories, including major-specific exclusions.
---

# Check the PostgreSQL backend behind a website

Use a saved observation from the named primary or replica. Record `server_version` and `server_version_num` from the same backend session or administrator's monitoring export. For example, PostgreSQL 16.16 reports 160016. Both a JSON integer and a canonical decimal string are accepted for the numeric value. A `psql` or libpq client version identifies different software. [PostgreSQL version fields](https://www.postgresql.org/docs/current/runtime-config-preset.html) · [Server version numbering](https://www.postgresql.org/docs/current/libpq-status.html#LIBPQ-PQSERVERVERSION)

Start with the [affected backend](examples/gap.json), [fixed backend](examples/pass.json), and [conflicting server records](examples/unknown.json). Repeat the protected asset and build aliases inside `evidence`, supply a record reference, and set `source` to `connected_server` for a backend observation.

```sh
python3 scripts/check.py < examples/gap.json
```

Each number in the last column completes a `CVE-2026-` identifier. Supply the full identifier. The checker returns that advisory's original PostgreSQL bulletin with its result. PostgreSQL records 12 November 2026 as the fix date for all the listed releases. [PostgreSQL security advisories](https://www.postgresql.org/support/security/)

| Reviewed affected majors | First fixed releases | Advisory numbers |
| --- | --- | --- |
| 14–18 | 14.25, 15.20, 16.16, 17.12, 18.7 | 116303, 116304, 116306, 116311, 116315, 116316, 116317, 116321, 116327, 116331, 116332, 116335, 116336, 120139, 120141, 120143, 120145, 120146, 120148, 120149, 120150, 120153, 120154 |
| 15–18 | 15.20, 16.16, 17.12, 18.7 | 116312 |
| 16–18 | 16.16, 17.12, 18.7 | 116328, 120152 |
| 17–18 | 17.12, 18.7 | 116310, 116333, 120142 |
| 18 | 18.7 | 116322, 116329, 120144 |

This saved upstream backend reports 17.11. It is `outside_affected_range` for CVE-2026-116322. Changing only the advisory to CVE-2026-116333 yields `affected_version` with first fix 17.12. Applicability stays `unknown` in both cases. [PostgreSQL 18-only bulletin](https://www.postgresql.org/support/security/CVE-2026-116322/) · [PostgreSQL 17–18 bulletin](https://www.postgresql.org/support/security/CVE-2026-116333/)

```json
{
  "advisory": "CVE-2026-116322", "asset": "training-replica", "build": "db-17",
  "evidence": {
    "asset": "training-replica", "build": "db-17", "ref": "session-export-7",
    "product": "postgresql", "origin": "upstream", "source": "connected_server",
    "server_version": "17.11", "server_version_num": 170011
  }
}
```

This edition reviews majors 14 through 18. Within them, report `outside_affected_range` when the publisher explicitly excludes an older major for that advisory. Other majors, conflicting observations, prereleases, and distributor or managed-service backports return `unknown`. Even where the upstream fix is present, support lifecycle is a separate decision. [PostgreSQL November release](https://www.postgresql.org/about/news/postgresql-187-1712-1616-1520-1425-and-19-rc-2-released-3442/)

For the client, identify the specific backend, build, version, advisory and evidence reference. Repeat the review for other replicas or pool members that serve the application. The upstream version verdict establishes neither use of an affected feature nor application exposure.

Separately loadable components require their own provenance. For example, CVE-2026-120151 affects PL/pgSQL, which can be installed and loaded separately. A backend version alone leaves the loaded module's patch status unknown. [PL/pgSQL overview](https://www.postgresql.org/docs/18/plpgsql-overview.html) · [PL/pgSQL advisory](https://www.postgresql.org/support/security/CVE-2026-120151/)
