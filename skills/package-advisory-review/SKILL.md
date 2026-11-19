---
name: package-advisory-review
description: Match every package in a deployed build's inventory against an offline OSV advisory snapshot for npm, Composer (Packagist) and Debian packages. Breadth review with unreviewed, mechanical results; flags CISA KEV listings and malicious releases.
---

# Review deployed packages against an OSV snapshot

Use this guide when an administrator wants a broad answer for a deployed build: which installed npm, Composer or Debian packages fall inside a published advisory. The checker compares the build's package inventory with an OSV snapshot the administrator downloaded beforehand. It never contacts the website or an advisory service.

Results are **unreviewed**. They come from OSV records that ARTEX maintainers have not checked against the vendor bulletins. When a hand-reviewed skill covers the same advisory, such as [framework patch review](../framework-patch-review/SKILL.md) or [runtime patch review](../runtime-patch-review/SKILL.md), report that skill's result as authoritative and this one as supporting breadth.

## Collect the evidence

Take every list from the artifact that is actually deployed, such as the production image or release bundle. A developer workstation or an unbuilt lockfile leaves the deployed packages unknown.

| Ecosystem | `ecosystem` value | Where to read `name` and `version` |
| --- | --- | --- |
| Composer | `Packagist` | `vendor/composer/installed.json` in the deployed build. Composer names are case-insensitive, and a leading `v` is accepted. Packages from packages.drupal.org also use `Packagist`. |
| npm | `npm` | `node_modules/.package-lock.json` in the deployed build. Versions must be exact SemVer 2.0 strings. |
| Debian | `Debian:<release>`, for example `Debian:12` | On the running system or image: `dpkg-query -W -f='${source:Package} ${source:Version}\n'`. Debian advisories name **source** packages (`openssl`, not `libssl3`) and source versions. Set `"source_package": true` only for entries taken this way. |

Download the matching OSV exports on a connected machine, for example `https://osv-vulnerabilities.storage.googleapis.com/Packagist/all.zip`, `.../npm/all.zip` and `.../Debian/all.zip`. Copy them to the review machine without unpacking. To flag known exploitation, also download the CISA Known Exploited Vulnerabilities catalog (`known_exploited_vulnerabilities.json`). The result records each file's SHA-256 and the newest record time, so cite them.

## Run the checker

From the unpacked skill directory, with Python 3.9 or later:

```sh
python3 scripts/check.py < examples/gap.json
python3 scripts/check.py --osv Packagist=Packagist-all.zip --osv npm=npm-all.zip \
  --osv Debian=Debian-all.zip --kev known_exploited_vulnerabilities.json < inventory.json
```

The input is one JSON object, as in the [affected](examples/gap.json), [no match](examples/pass.json) and [unknown](examples/unknown.json) examples. Supply an `inventory` with these fields:

- `asset`, `build` and `ref`: redacted identifiers for the deployed build and the inventory artifact.
- `deployment_verified`: set this to true only when that artifact ties the list to the deployed build.
- `packages`: up to 20,000 entries.

The examples embed a small synthetic `snapshot`; real reviews pass the export files with `--osv`. Each `--osv` value names the export's family (`npm`, `Packagist` or `Debian`).
- A file that doesn't mostly contain that family's records doesn't count as a snapshot.
- A snapshot is `complete` when every record in it was read.
- Records whose ranges break the OSV schema are counted in `damaged_ranges`. They make only the packages they name `unknown`.
- The checker can't tell a partial download from the full export, so use the official `all.zip` and cite its SHA-256.

Two rules keep results conservative:
- **Composer versions** are compared under Composer's ordering and under OSV's own Packagist ordering, which is PHP's `version_compare`. The two disagree on short forms and prereleases: OSV sorts `8.4` before `8.4.0`, and `1.10.0-alpha` after `1.10`. When they disagree, that record is inconclusive.
- **Debian coverage is judged per release.** OSV's fixed-advisory records (DSA/DLA) can't show that a release's open issues are tracked. So `no_matching_advisory` needs security-tracker records (`DEBIAN-*`) for that release, from a source declared as Debian.
  - The threshold is at least a quarter of the count for the best-covered release in the loaded data. This is a heuristic, relative to what was loaded.
  - When this skill was written, Debian 12–14 each had over 55,000 tracker entries. Debian 11 had about 1,200 and older releases had none.
  - Affected matches on an uncovered release are still reported.

## Interpret the result in ARTEX

Report `review_level` (`unreviewed`), the asset, build and inventory reference, each snapshot's source, SHA-256 and `newest_modified`, and the KEV catalog version. Then report each package's `status`:

- `affected` means at least one non-withdrawn OSV record covers the installed version.
  - Name each advisory ID and CVE, and give `fixed_in` as the published fix to plan against.
  - `kev_date_added` means CISA lists that CVE as exploited in the wild. Treat it as the top remediation priority.
  - `malicious` means the record reports a malicious release. Treat the build as potentially compromised and follow the owner's incident process rather than only upgrading.
  - Debian's own `distribution_urgency` is passed through, taken from the entry for the matched release. A value such as `unimportant` is Debian's triage, not a clean result.
  - `wildcard_package` means the record covers every package in that ecosystem or release, for example an end-of-life notice.
- `unknown` means the checker could not reach a conclusion. Use `reason` to ask for the missing evidence:
  - an inventory tied to the deployed build;
  - a supported ecosystem;
  - a complete snapshot for that ecosystem;
  - Debian source package names, and a release suffix such as `Debian:12`;
  - a standard version string.

  It is also `unknown` when Composer's and OSV's version orderings disagree, or when the loaded Debian data doesn't track open issues for that release.

  It is also `unknown` when a record cannot be evaluated conclusively. One example is a version above a `last_affected` ceiling with no published fix, which can still be vulnerable. The advisory list shows each inconclusive record and why.
- `no_matching_advisory` means no record in the loaded snapshot covers this version. It is **not** a fix verdict:
  - OSV can lag vendor bulletins. When this skill was written, it lacked two advisories this pack reviews by hand.
  - It also cannot see local patches, vendored copies or packages missing from the inventory.
  - Repeat with a fresh snapshot after each upgrade.

Report an `invalid_input` result as a request to correct the inventory, the snapshot paths or the options. This release supports npm, Composer and Debian. Other ecosystems return `unknown` until their version ordering is added and tested.
