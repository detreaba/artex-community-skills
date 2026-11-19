---
name: sslyze-legacy-tls-review
description: Interpret saved SSLyze JSON results for TLS 1.0 and TLS 1.1 on direct TLS endpoints. Report accepted legacy protocols, explicit version rejections and gaps in test coverage.
---

# Review recorded TLS 1.0 and TLS 1.1 observations

Use an administrator’s SSLyze JSON export. This skill reads each recorded endpoint and its two legacy protocol command results. RFC 8996 deprecates both versions. A completed SSLyze export can contain failed endpoints and individual commands that were never scheduled. [SSLyze JSON format](https://github.com/nabla-c0d3/sslyze/blob/6.3.1/json_output_schema.json) · [RFC 8996](https://www.rfc-editor.org/rfc/rfc8996)

Run the reader locally on an existing report and give ARTEX its JSON summary. The examples contain synthetic names and addresses. The input is the native SSLyze report object, bounded to 32 MiB and a combined 512 endpoint results and invalid target entries.

```sh
python3 scripts/check.py < examples/gap.json
```

The reader accepts reports identifying SSLyze 6.1.0, 6.2.0, 6.3.0 or 6.3.1. It covers direct TLS with a recorded peer IP, port and SNI and without client credentials. Proxy connections, STARTTLS, incomplete scope and unsupported producer versions yield `unknown`. The output contains endpoint identifiers, observation times and a SHA-256 digest of the input bytes. Keep the original report with the administrator. [SSLyze export documentation](https://github.com/nabla-c0d3/sslyze/blob/6.3.1/docs/json-output.rst)

| Protocol result | Evidence and client interpretation |
| --- | --- |
| `gap` | The completed command reports the protocol as supported and lists an accepted cipher suite. Report the protocol and endpoint as an observed configuration finding. Application exploitability requires separate evidence. |
| `pass` | The completed command lists zero accepted suites, reports no support and records an explicit protocol-version alert for every tested suite. State that the reported attempts received version rejections. |
| `unknown` | The command is absent or incomplete, the records conflict, or the negative results include an ambiguous handshake error. SSLyze can record a timeout as a rejected suite. |

Preserve both the report’s `status` and its `coverage`. An accepted protocol produces `gap` even if another endpoint failed. Invalid target entries, skipped commands or unreachable endpoints produce incomplete coverage. An empty report has unknown status. `complete_for_reported_endpoints` covers these two checks at the recorded hostnames, addresses, ports, SNI names and times. Other hostnames, TLS versions and certificate validity are separate assessments. [SSLyze handshake result handling](https://github.com/nabla-c0d3/sslyze/blob/6.3.1/sslyze/plugins/openssl_cipher_suites/_test_cipher_suite.py)

Compare the [legacy protocol example](examples/gap.json), [explicit rejection example](examples/pass.json) and [timeout and skipped command example](examples/unknown.json). The fixtures use the native report structure and were validated against the upstream 6.3.1 schema. Each endpoint record has a UUID and a row number so an administrator can locate the evidence in the original report. [SSLyze sample export](https://github.com/nabla-c0d3/sslyze/blob/6.3.1/tests/json_tests/sslyze_output.json)
