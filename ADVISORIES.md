# Advisory coverage

Reviewed 19 November 2026. These checks compare an administrator's deployment inventory with a named upstream bulletin. Each reports patch status and the available evidence about relevant features separately. Distribution packages can include backported fixes and need a package-specific vendor decision.

| Published | Component | Vendor advisory | Skill |
| --- | --- | --- | --- |
| 19 Nov 2026 | PHP session handling | [CVE-2026-115560](https://github.com/php/php-src/security/advisories/GHSA-658j-r8rw-q6mx) | Runtime patch review |
| 19 Nov 2026 | PHP-FPM status display | [CVE-2026-129292](https://github.com/php/php-src/security/advisories/GHSA-3mg3-cr28-46gc) | Runtime patch review |
| 19 Nov 2026 | PHP-CGI path handling | [CVE-2026-129538](https://github.com/php/php-src/security/advisories/GHSA-5j3f-64r7-f564) | Runtime patch review |
| 18 Nov 2026 | Drupal core installer | [CVE-2026-132165](https://www.drupal.org/sa-core-2026-017) | Framework patch review |
| 11 Nov 2026 | Node.js HTTP/2 | [CVE-2026-123865](https://nodejs.org/en/blog/vulnerability/november-2026-security-releases) | Runtime patch review |
| 4 Nov 2026 | Symfony HTTP Foundation method restrictions | [CVE-2026-118514](https://symfony.com/blog/cve-2026-118514-head-requests-bypass-the-methods-option-of-access-control-and-firewalls-incomplete-fix-for-cve-2026-45075) | Framework patch review |
| 3 Nov 2026 | Next.js cache and binary arguments | [CVE-2026-119349](https://github.com/vercel/next.js/security/advisories/GHSA-rhh4-g77r-r9qj) | Framework patch review |
| 3 Nov 2026 | Next.js nested cache and root parameters | [CVE-2026-119351](https://github.com/vercel/next.js/security/advisories/GHSA-vc7v-qv4w-wrv8) | Framework patch review |
| 3 Nov 2026 | Django page cache | [CVE-2026-113593](https://www.djangoproject.com/weblog/2026/nov/03/security-releases/) | Framework patch review |
| 3 Nov 2026 | Django admin user model | [CVE-2026-113733](https://docs.djangoproject.com/en/6.1/releases/security/#november-3-2026-cve-2026-113733) | Framework patch review |

Consult the individual skill guide for the input fields, release branches, and conditions the checker can assess. Page headers and a framework name alone leave the deployed patch status unknown. [Runtime guide](skills/runtime-patch-review/SKILL.md) · [Framework guide](skills/framework-patch-review/SKILL.md)
