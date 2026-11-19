# ARTEX Community Skills

Three independent skills for website administrators. Each uses a small offline checker to answer a specific security question from evidence you already have. Each download includes the ARTEX guide, the checker, synthetic examples and tests. The checkers use the Python 3.9+ standard library.

| Skill | Question it answers | Evidence you need |
| --- | --- | --- |
| [Browser controls](skills/browser-controls/SKILL.md) | Does this HTML response declare a content security policy, framing protection and MIME-sniffing protection? | Captured status, headers and decoded document head. |
| [Runtime patch review](skills/runtime-patch-review/SKILL.md) | Does this serving PHP or Node.js runtime include the upstream fix for a supported advisory? | Exact runtime version and origin from the deployed process. Configuration evidence can establish which affected features are in use. |
| [Authorization matrix](skills/authorization-matrix/SKILL.md) | Do recorded access decisions agree with the owner's role and tenant policy? | A versioned policy and saved allow/deny results for the same build, role, resource and operation. |

## Try one in a minute

From the repository root, run the example for a page missing a browser control.

```bash
cd skills/browser-controls
python3 scripts/check.py < examples/gap.json
```

Read the rule for CSP (`WEB-CSP-01`), then repeat with `examples/pass.json` and `examples/unknown.json`. The examples show how the result changes when evidence is present, a control is missing, or the available data is insufficient. A missing CSP on one response is a configuration finding for that response.

## Use a skill in ARTEX

1. Choose the ZIP named after the skill in **GitHub Releases**, or build it from source with the command below. ARTEX imports one skill per archive.
2. In **System → Skills**, select **Upload archive** and upload that ZIP. Open the installed skill and enable it for operator **Chat** under the agent visibility settings. If your installation already has a skill with that name, compare the guides before replacing it.
3. Run the bundled checker locally on a redacted evidence file. From the unpacked skill folder, use `python3 scripts/check.py < evidence.json`.
4. In operator Chat, ask it to load the skill by name. Paste the checker result and a reference for the inspected build, page or test run. For example, “Load browser-controls. Explain these three results for the captured homepage and list what remains unknown.” Treat a fixture result as a demonstration. Use the client's own records for a client finding.

The public guides can interpret pasted checker results in a fresh ARTEX installation. They require no MCP server, custom tool registration, model shell access or API key. The independent checkers can also be used without ARTEX.

## Build release files

```bash
python3 tools/package_skills.py
```

The build creates one ZIP per skill in `dist/` plus `SHA256SUMS`. On Linux, run `(cd dist && sha256sum -c SHA256SUMS)` to check the archives against the manifest. A release maintainer can attach all three ZIPs and the checksum file to a tagged GitHub Release. [GitHub Releases](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases)

## Contribute a skill or advisory

Open an issue describing the administrative decision, the evidence an owner can provide, and the expected result when evidence is missing. For a pull request, include a short ARTEX guide, an offline checker, synthetic gap/pass/unknown examples, and tests with independently stated expectations. Never submit real client records or credentials. For a CVE update, link the vendor bulletin and test the versions immediately below and at the documented fix. Add a rule to an existing skill when it uses the same evidence and decision.

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
