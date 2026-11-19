---
name: browser-controls
description: Interpret an administrator's offline review of CSP delivery, framing, and MIME sniffing on one saved HTML response. Use when a website owner supplies a capture or the reviewer's JSON results.
---

# Review browser controls on a captured page

Work from the JSON produced by this skill's checker. If the administrator has only a capture, give them the local command below and ask them to supply the result, a redacted capture reference, and the page or build it represents. If they have only a URL, the three controls remain unknown. The checker reads its input from standard input and makes no network requests.

## Prepare the input

From this skill's directory, an administrator can run a synthetic example with Python 3.9 or later.

```sh
python3 scripts/check.py < examples/gap.json
```

For a real review, replace the example with a JSON object containing the numeric response `status`, every occurrence of the relevant `headers`, and optionally `html_head` and `html_complete`. Preserve Content-Type, both CSP header forms, X-Frame-Options, and X-Content-Type-Options. Use ordered name/value pairs for repeated headers. Omit cookies, tokens, and unrelated headers. Keep the decoded HTML local. It must start at the beginning of the document. Set `html_complete` to true only when the supplied text includes the entire head.

## Explain the result

Keep a separate row for each returned rule. Preserve its status and short evidence statement.

| Rule | Question answered |
| --- | --- |
| `WEB-CSP-01` | Does an enforcing header or an eligible head meta element declare a recognized CSP control? A report-only policy permits observation without enforcement. |
| `WEB-FRAME-01` | Does the response declare a recognized framing restriction? For a custom list of origins, review the site's permitted embedding partners. |
| `WEB-MIME-01` | Does the response declare effective `nosniff` handling? |

`present` describes the specific declaration. Assess policy strength and behavior on other pages separately. For a `gap`, cite the capture, explain the missing declaration, and identify the same response to capture after remediation. For `unknown`, name the missing information. `not_applicable` describes responses outside the checker's full HTML document scope. An `invalid_input` result requires a corrected input before a verdict.

The three examples exercise absent controls, present controls and missing response classification. [Gap fixture](examples/gap.json) · [Present fixture](examples/pass.json) · [Unknown fixture](examples/unknown.json) · [Content Security Policy specification](https://www.w3.org/TR/CSP3/)
