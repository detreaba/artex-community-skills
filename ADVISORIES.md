# Advisory coverage

Reviewed 19 November 2026. These checks compare an administrator's deployment inventory with a named upstream bulletin. Each reports patch status and the available evidence about relevant features separately. Distribution packages can include backported fixes and need a package-specific vendor decision.

| Published | Component | Vendor advisory | Skill |
| --- | --- | --- | --- |
| 19 Nov 2026 | PHP session handling | [CVE-2026-115560](https://github.com/php/php-src/security/advisories/GHSA-658j-r8rw-q6mx) | Runtime patch review |
| 19 Nov 2026 | PHP-FPM status display | [CVE-2026-129292](https://github.com/php/php-src/security/advisories/GHSA-3mg3-cr28-46gc) | Runtime patch review |
| 19 Nov 2026 | PHP-CGI path handling | [CVE-2026-129538](https://github.com/php/php-src/security/advisories/GHSA-5j3f-64r7-f564) | Runtime patch review |
| 11 Nov 2026 | Node.js HTTP/2 | [CVE-2026-123865](https://nodejs.org/en/blog/vulnerability/november-2026-security-releases) | Runtime patch review |
| 4 Nov 2026 | Symfony HTTP Foundation method restrictions | [CVE-2026-118514](https://symfony.com/blog/cve-2026-118514-head-requests-bypass-the-methods-option-of-access-control-and-firewalls-incomplete-fix-for-cve-2026-45075) | Framework patch review |
| 3 Nov 2026 | Next.js cache and binary arguments | [CVE-2026-119349](https://github.com/vercel/next.js/security/advisories/GHSA-rhh4-g77r-r9qj) | Framework patch review |
| 3 Nov 2026 | Next.js nested cache and root parameters | [CVE-2026-119351](https://github.com/vercel/next.js/security/advisories/GHSA-vc7v-qv4w-wrv8) | Framework patch review |
| 3 Nov 2026 | Django page cache | [CVE-2026-113593](https://www.djangoproject.com/weblog/2026/nov/03/security-releases/) | Framework patch review |
| 3 Nov 2026 | Django admin user model | [CVE-2026-113733](https://docs.djangoproject.com/en/6.1/releases/security/#november-3-2026-cve-2026-113733) | Framework patch review |

Consult the individual skill guide for the input fields, release branches, and conditions the checker can assess. Page headers and a framework name alone leave the deployed patch status unknown. [Runtime guide](skills/runtime-patch-review/SKILL.md) · [Framework guide](skills/framework-patch-review/SKILL.md)

## Web and database infrastructure

| Published | Skill | Advisories |
| --- | --- | --- |
| 18 Nov 2026 | [NGINX worker](skills/nginx-worker-patch-review/SKILL.md) | CVE-2026-123634, CVE-2026-123007, CVE-2026-121810, CVE-2026-123633, CVE-2026-118899, CVE-2026-113425, CVE-2026-120993, CVE-2026-125283, CVE-2026-120967, CVE-2026-123640. [NGINX advisories](https://nginx.org/en/security_advisories.html) |
| 12 Nov 2026 | [PostgreSQL server](skills/postgres-server-patch-review/SKILL.md) | [CVE-2026-116316](https://www.postgresql.org/support/security/CVE-2026-116316/), [CVE-2026-120145](https://www.postgresql.org/support/security/CVE-2026-120145/), [CVE-2026-116310](https://www.postgresql.org/support/security/CVE-2026-116310/), [CVE-2026-116328](https://www.postgresql.org/support/security/CVE-2026-116328/) |
| 11 Nov 2026 | [Apache module](skills/apache-module-patch-review/SKILL.md) | [CVE-2026-119618](https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2026-119618), [CVE-2026-106023](https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2026-106023), [CVE-2026-109163](https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2026-109163) |
