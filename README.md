# ARTEX Community Skills

Independent ARTEX skills for website administrators. Each uses a small offline checker to answer a specific security question from evidence you already have. Each download includes the ARTEX guide, the checker, synthetic examples and tests. The checkers use the Python 3.9+ standard library.

| Skill | Question it answers | Evidence you need |
| --- | --- | --- |
| [Browser controls](skills/browser-controls/SKILL.md) | Does this HTML response declare a content security policy, framing protection and MIME-sniffing protection? | Captured status, headers and decoded document head. |
| [Runtime patch review](skills/runtime-patch-review/SKILL.md) | Does this serving PHP or Node.js runtime include the upstream fix for a supported advisory? | Exact runtime version and origin from the deployed process. Configuration evidence can establish which affected features are in use. |
| [Framework patch review](skills/framework-patch-review/SKILL.md) | Does a deployed Next.js, Django or Symfony package fall within a vendor advisory’s affected releases? | A deployment-specific package record and, when available, same-build evidence of the relevant application feature. |
| [Authorization matrix](skills/authorization-matrix/SKILL.md) | Do recorded access decisions agree with the owner's role and tenant policy? | A versioned policy and saved allow/deny results for the same build, role, resource and operation. |

Release v0.1.0 includes nine advisory checks. The catalog lists every advisory supported by this checkout. [Advisory catalog](ADVISORIES.md)

## Try one in a minute

From the repository root, run the example for a page missing a browser control.

```bash
cd skills/browser-controls
python3 scripts/check.py < examples/gap.json
```

Read the rule for CSP (`WEB-CSP-01`), then repeat with `examples/pass.json` and `examples/unknown.json`. The examples show how the result changes when evidence is present, a control is missing, or the available data is insufficient. A missing CSP on one response is a configuration finding for that response.

## Use a skill in ARTEX

1. Choose the ZIP named after the skill in [GitHub Releases](https://github.com/detreaba/artex-community-skills/releases), or build it from source with the command below. ARTEX imports one skill per archive.
2. In **System → Skills**, select **Upload archive** and upload that ZIP. Open the installed skill and enable it for operator **Chat** under the agent visibility settings. If your installation already has a skill with that name, compare the guides before replacing it.
3. Run the bundled checker locally on a redacted evidence file. From the unpacked skill folder, use `python3 scripts/check.py < evidence.json`.
4. In operator Chat, ask it to load the skill by name. Paste the checker result and a reference for the inspected build, page or test run. For example, “Load browser-controls. Explain these three results for the captured homepage and list what remains unknown.” Treat a fixture result as a demonstration. Use the client's own records for a client finding.

The public guides can interpret pasted checker results in a fresh ARTEX installation. They require no MCP server, custom tool registration, model shell access or API key. The independent checkers can also be used without ARTEX.

## Review the infrastructure serving a website

| Skill | Advisory coverage | Evidence for one instance |
| --- | --- | --- |
| [NGINX worker patch review](skills/nginx-worker-patch-review/SKILL.md) | Ten advisories in the November 18 upstream release | The executable version of a running NGINX Open Source worker. |
| [Apache module patch review](skills/apache-module-patch-review/SKILL.md) | Three advisories in Apache HTTP Server 2.4.71 | The active module's provenance and release, including a separately supplied upstream mod_h2. |
| [PostgreSQL server patch review](skills/postgres-server-patch-review/SKILL.md) | Four November 12 core-server advisories | Matching text and numeric versions for the same connected database backend. |

Build these ZIPs from this checkout. Each includes its checker, shared evidence reader, tests and three synthetic cases. Apply the recorded result to the identified process or instance. A fleet-wide claim requires evidence from every serving member.

## Build release files

```bash
python3 tools/package_skills.py
```

The build creates one ZIP per skill in `dist/` plus `SHA256SUMS`. On Linux, run `(cd dist && sha256sum -c SHA256SUMS)` to check the archives against the manifest. A release maintainer can attach the skill ZIPs and the checksum file to a tagged GitHub Release. [GitHub Releases](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases)

## Contribute a skill or advisory

Open an issue describing the administrative decision, the evidence an owner can provide, and the expected result when evidence is missing. For a pull request, include a short ARTEX guide, an offline checker, synthetic gap/pass/unknown examples, and tests with independently stated expectations. Never submit real client records or credentials. For a CVE update, link the vendor bulletin and test the versions immediately below and at the documented fix. Add a rule to an existing skill when it uses the same evidence and decision.

Maintainers review one advisory at a time. Start with the publisher's bulletin and affected branches. Track corrections, package aliases, downstream fixes and any configuration evidence needed for interpreting the result. Give priority to an issue that applies to software administrators actually deploy. A CISA Known Exploited Vulnerabilities listing adds priority when applicable. Cite attribution to AI-assisted discovery only when the publisher explicitly documents it. [CISA catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

Run the tests from the root before proposing a release.

```bash
python3 -m unittest discover -s tests
for skill in skills/*; do
  (cd "$skill" && python3 -m unittest discover -s tests) || exit 1
done
```

## Compatibility and license

Tested with the Go ARTEX ZIP importer in checkout `65045ef`. This is an independent community collection for the ARTEX project originally created by Autumn-27 and continued by BaaRai. [ARTEX project](https://github.com/BaaRai/ARTEX)

The collection is distributed under the GNU Affero General Public License, version 3. [License](LICENSE)
