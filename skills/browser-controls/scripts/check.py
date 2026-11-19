"""Offline checks of supplied HTTP response data. Output contains no raw header or body values."""

import json
import re
import sys
from collections.abc import Mapping
from html.parser import HTMLParser

RULE_IDS = ("WEB-CSP-01", "WEB-FRAME-01", "WEB-MIME-01")
HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
RELEVANT = {"content-type", "content-security-policy", "content-security-policy-report-only",
            "x-frame-options", "x-content-type-options"}
CSP_CONTROLS = set("""
    base-uri block-all-mixed-content child-src connect-src default-src fenced-frame-src
    font-src form-action frame-ancestors frame-src img-src manifest-src media-src object-src
    require-trusted-types-for sandbox script-src script-src-attr script-src-elem style-src
    style-src-attr style-src-elem trusted-types upgrade-insecure-requests worker-src
""".split())
META_IGNORED = {"frame-ancestors", "sandbox", "report-uri", "report-to"}
META_CONTROLS = CSP_CONTROLS - META_IGNORED
ASCII_WHITESPACE = re.compile(r"[ \t\n\r\f]+")


def _read_headers(headers):
    if not isinstance(headers, (Mapping, list, tuple)) or len(headers) > 256:
        raise ValueError("Provide at most 256 response header fields.")
    selected = {name: [] for name in RELEVANT}
    fields = headers.items() if isinstance(headers, Mapping) else headers
    length = 0
    for pair in fields:
        if not isinstance(pair, (tuple, list)) or len(pair) != 2:
            raise ValueError("Each response header must have a name and a string value.")
        name, value = pair
        if not isinstance(name, str) or not isinstance(value, str):
            raise ValueError("Header names and values must be strings.")
        length += len(name) + len(value)
        if length > 131072 or not HEADER_NAME.fullmatch(name) or any(c in value for c in "\r\n\0"):
            raise ValueError("Headers exceed the size limit or contain invalid characters.")
        if name.lower() in RELEVANT:
            selected[name.lower()].append(value.strip(" \t"))
    return selected


def _policies(values):
    """Each comma-separated policy applies, and the first duplicate directive wins."""
    for field in values:
        for policy in field.split(","):
            directives = {}
            for raw in policy.split(";"):
                parts = ASCII_WHITESPACE.split(raw.strip(" \t\n\r\f"))
                if parts[0]:
                    directives.setdefault(parts[0].lower(), parts[1:])
            yield directives


class _HeadPolicies(HTMLParser):
    # These elements cannot contain an effective CSP meta tag with scripting enabled.
    CDATA_CONTENT_ELEMENTS = (*HTMLParser.CDATA_CONTENT_ELEMENTS, "title", "noscript", "noframes")
    HEAD_ELEMENTS = {"html", "head", "base", "basefont", "bgsound", "link", "meta",
                     "title", "noscript", "noframes", "style", "script", "template"}

    def __init__(self):
        super().__init__()
        self.phase = "head"  # HTML allows the opening head tag to be omitted.
        self.template_depth = 0
        self.raw_element = None
        self.values = []
        self.ambiguous = False

    def handle_starttag(self, tag, attrs):
        if self.phase == "body":
            return
        if tag == "template":
            self.template_depth += 1
        if self.template_depth:
            return
        if tag not in self.HEAD_ELEMENTS:
            self.phase = "body"
        elif tag in self.CDATA_CONTENT_ELEMENTS:
            self.raw_element = tag
        elif tag == "meta":
            # HTML keeps the first attribute when the name is repeated.
            fields = dict(reversed(attrs))
            if (fields.get("http-equiv") or "").lower() == "content-security-policy":
                if self.phase == "head":
                    self.values.append(fields.get("content") or "")
                else:
                    self.ambiguous = True

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)  # HTML ignores self-closing slashes on non-void elements.

    def handle_endtag(self, tag):
        if self.template_depth:
            if tag == "template":
                self.template_depth -= 1
        elif tag == self.raw_element:
            self.raw_element = None
        elif tag == "head" and self.phase == "head":
            self.phase = "after_head"
        elif tag in ("body", "html"):
            self.phase = "body"

    def handle_data(self, data):
        if not self.template_depth and not self.raw_element and data.strip(" \t\f\r\n"):
            self.phase = "body"


def _csp(h, policies, html, complete):
    if any(CSP_CONTROLS.intersection(policy) for policy in policies):
        return "present", "An enforcing CSP response header declares a recognized control."
    seen_unclassified = any(set(p) - {"report-to", "report-uri"} for p in policies)
    if html is not None:
        parser = _HeadPolicies()
        try:
            parser.feed(html)
            parser.close()
        except (AssertionError, ValueError, RecursionError):
            return "unknown", "The supplied HTML head could not be parsed reliably."
        meta_policies = list(_policies(parser.values))
        if any(META_CONTROLS.intersection(p) for p in meta_policies):
            return "present", "An enforcing CSP meta element declares a recognized control in the HTML head."
        if parser.ambiguous:
            return "unknown", "A CSP meta element occurs between the head and body in ambiguous markup."
        seen_unclassified |= any(set(p) - META_IGNORED for p in meta_policies)
        complete = complete or parser.phase == "body"
    if seen_unclassified:
        return "unknown", "A policy was supplied without a recognized applicable control."
    if html is None or not complete:
        return "unknown", "No enforcing CSP header was seen. The complete HTML head is unavailable."
    if any(h["content-security-policy-report-only"]):
        return "gap", "Only a report-only CSP was seen in the supplied response."
    return "gap", "No applicable enforcing CSP control was found in the headers or HTML head."


def _framing(h, policies):
    ancestors = [p["frame-ancestors"] for p in policies if "frame-ancestors" in p]
    if ancestors:
        if any([s.lower() for s in sources] in (["'self'"], ["'none'"]) for sources in ancestors):
            return "present", "An enforced frame-ancestors directive restricts embedding to self or none."
        if all(s == ["*"] for s in ancestors):
            return "gap", "The enforced frame-ancestors wildcard allows broad embedding and overrides X-Frame-Options."
        return "unknown", "Review the custom frame-ancestors sources against the permitted embedding origins."
    options = {s.strip(" \t").lower() for value in h["x-frame-options"] for s in value.split(",")}
    if options in ({"deny"}, {"sameorigin"}):
        return "present", "The X-Frame-Options header declares DENY or SAMEORIGIN."
    if options:
        return "unknown", "X-Frame-Options has an unsupported or conflicting value."
    return "gap", "No enforced frame-ancestors directive or X-Frame-Options header was seen."


def review_response(status, headers, html_head=None, html_complete=False):
    """Review a final response. html_head starts at the beginning of decoded HTML.

    Set html_complete only for the complete document or the complete head. Supply
    every occurrence of the relevant headers, including duplicates. Input limits
    are 256 header fields, 131072 header characters and 262144 HTML characters.
    """
    if type(status) is not int or not 100 <= status <= 599:
        raise ValueError("status must be an HTTP status integer.")
    if type(html_complete) is not bool or (html_head is not None and
            (not isinstance(html_head, str) or len(html_head) > 262144)):
        raise ValueError("Provide bounded decoded HTML and a boolean completeness flag.")
    h = _read_headers(headers)
    media = [v.partition(";")[0].strip().lower() for v in h["content-type"]]
    limits = ["Results describe only the supplied response and declared controls. "
              "Policy strength, application vulnerabilities and browser runtime behavior require separate evidence."]
    if not 200 <= status < 300 or status in (204, 205, 206):
        results = [("not_applicable", "These checks apply to successful, full document responses.")] * 3
    elif len(media) != 1 or not media[0] or "," in media[0]:
        results = [("unknown", "A single unambiguous Content-Type is required to classify the document.")] * 3
    elif media[0] != "text/html":
        results = [("not_applicable", "These checks apply to text/html documents.")] * 3
    else:
        policies = list(_policies(h["content-security-policy"]))
        nosniff = h["x-content-type-options"]
        # Fetch tests the first item of the decoded header list.
        mime = (("present", "The first X-Content-Type-Options value is nosniff.")
                if nosniff and nosniff[0].split(",", 1)[0].strip(" \t").lower() == "nosniff"
                else ("gap", "The response lacks an effective nosniff header value."))
        results = [_csp(h, policies, html_head, html_complete), _framing(h, policies), mime]
        limits.append("HTML meta evaluation assumes ordinary static head markup with scripting enabled.")
    return {"scope": "response_configuration",
            "rules": [{"id": name, "status": state, "evidence": evidence}
                      for name, (state, evidence) in zip(RULE_IDS, results)],
            "limitations": limits}


def _unique_fields(pairs):
    fields = dict(pairs)
    if len(fields) != len(pairs):
        raise ValueError("Duplicate JSON fields.")
    return fields


def main():
    limit = 2 * 1024 * 1024
    try:
        raw = sys.stdin.buffer.read(limit + 1)
        if len(raw) > limit:
            raise ValueError("Input exceeds the size limit.")
        data = json.loads(raw, object_pairs_hook=_unique_fields)
        if not isinstance(data, dict):
            raise ValueError("Expected a response object.")
        result = review_response(**data)
    except (TypeError, ValueError, RecursionError):
        print(json.dumps({"error": "invalid_input", "detail": "Check the capture fields and size limits."}))
        return 2
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
