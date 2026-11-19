import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

CHECKER = Path(__file__).resolve().parents[1] / "scripts" / "check.py"
spec = importlib.util.spec_from_file_location("browser_controls_check", CHECKER)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)
review_response = checker.review_response


def decisions(headers=None, html=None, complete=False, status=200):
    supplied = {"Content-Type": "text/html", **(headers or {})}
    report = review_response(status, supplied, html, complete)
    return tuple(rule["status"] for rule in report["rules"])


class HeaderReviewTests(unittest.TestCase):
    def test_controls_repaired_individually(self):
        self.assertEqual(decisions(html="<html><body>ok</body></html>", complete=True), ("gap", "gap", "gap"))
        fixed = {"CONTENT-SECURITY-POLICY": "default-src 'self'; frame-ancestors 'none'",
                 "X-Content-Type-Options": "nosniff"}
        self.assertEqual(decisions(fixed), ("present", "present", "present"))

    def test_reporting_only_is_distinguished_from_enforcement(self):
        report = review_response(200, {"Content-Type": "text/html", "Content-Security-Policy-Report-Only":
                                      "default-src 'none'; frame-ancestors 'self'"}, "<body>", True)
        self.assertEqual(report["rules"][0]["status"], "gap")
        self.assertIn("report-only", report["rules"][0]["evidence"])
        self.assertEqual(report["rules"][1]["status"], "gap")

    def test_meta_in_head_counts_but_cannot_restrict_framing(self):
        markup = '<head><MeTa Http-Equiv="Content-Security-Policy" content="default-src a; frame-ancestors b"></head>'
        self.assertEqual(decisions(html=markup, complete=True), ("present", "gap", "gap"))

    def test_body_comments_templates_title_and_script_do_not_supply_a_head_policy(self):
        meta = '<meta http-equiv="Content-Security-Policy" content="default-src a">'
        for markup in (f"<head></head><body>{meta}</body>", f"<!-- {meta} -->",
                       f"<head><template><template>{meta}</template></template></head>",
                       f"<head><title>{meta}</title></head>", f"<head><script>{meta}</script></head>",
                       f"<head><noscript>{meta}</noscript></head>", f"<head><noframes>{meta}</noframes></head>",
                       f"<main>{meta}</main>"):
            with self.subTest(markup=markup):
                self.assertEqual(decisions(html=markup, complete=True)[0], "gap")

    def test_ambiguous_late_meta_and_truncated_head_are_inconclusive(self):
        self.assertEqual(decisions(html='<head></head><meta http-equiv="Content-Security-Policy" content="default-src a">', complete=True)[0], "unknown")
        for html in (None, '<head><title>Document</title>', '<head><meta http-equiv="Content-Security-'):
            self.assertEqual(decisions(html=html)[0], "unknown")
        self.assertEqual(decisions(html="<html><head></head><body>first bytes")[0], "gap")

    def test_duplicate_headers_and_directives_have_distinct_meanings(self):
        fields = [("Content-Type","text/html"), ("Content-Security-Policy", "default-src 'self'; frame-ancestors *; frame-ancestors 'none'"),
                  ("X-Frame-Options","DENY")]
        self.assertEqual(review_response(200, fields)["rules"][1]["status"], "gap")
        fields.append(("Content-Security-Policy", "frame-ancestors 'self'"))
        self.assertEqual(review_response(200, fields)["rules"][1]["status"], "present")

    def test_meta_only_unsupported_directives_do_not_clear_the_control(self):
        self.assertEqual(decisions(html='<meta http-equiv="Content-Security-Policy" content="frame-ancestors a">',complete=True)[:2],("gap","gap"))

    def test_non_ascii_separator_does_not_activate_a_directive(self):
        self.assertEqual(decisions({"Content-Security-Policy": "default-src\u00a0'self'"}, "<body>", True)[0], "unknown")

    def test_meta_with_duplicate_attributes_uses_first_value(self):
        html = '<head><meta http-equiv="other" http-equiv="content-security-policy" content="default-src a"></head>'
        self.assertEqual(decisions(html=html, complete=True)[0], "gap")

    def test_ambiguous_framing_is_reported_for_manual_review(self):
        self.assertEqual(decisions({"Content-Security-Policy":"frame-ancestors https://trusted.invalid"})[1], "unknown")
        self.assertEqual(decisions({"X-Frame-Options":"DENY, SAMEORIGIN"})[1], "unknown")
        self.assertEqual(decisions({"X-Frame-Options":"sameorigin"})[1], "present")

    def test_first_nosniff_token_is_authoritative(self):
        self.assertEqual(decisions({"X-Content-Type-Options":"invalid, nosniff"})[2], "gap")
        self.assertEqual(decisions({"X-Content-Type-Options":"Nosniff, invalid"})[2], "present")

    def test_non_html_partial_and_unknown_content_type(self):
        for status in (101, 204, 205, 206, 302, 304, 404):
            self.assertEqual(decisions(status=status), ("not_applicable",)*3)
        self.assertEqual(decisions({"Content-Type":"application/json"}), ("not_applicable",)*3)
        for h in ({}, [("Content-Type","text/html"), ("Content-Type","application/json")]):
            self.assertEqual({r["status"] for r in review_response(200,h)["rules"]},{"unknown"})

    def test_input_errors_and_reports_do_not_disclose_secrets(self):
        secret = "omitted-private-string"
        headers = {"Set-Cookie": secret, "Content-Security-Policy": "default-src "+secret,
                   "Content-Type":"text/html", "X-Public-Label":secret}
        self.assertNotIn(secret,json.dumps(review_response(200, headers)))
        for h, html in (({"Test":"x"*131073},None), ([("A","x")]*257,None),
                        ({secret:"a\ninvalid"},None), ({secret:[]},None), ({}, "x"*262145)):
            with self.assertRaises(ValueError) as ctx:
                review_response(200, h, html)
            self.assertNotIn(secret,str(ctx.exception))

    def test_cli_rejects_ambiguous_or_oversized_input(self):
        for raw in (
            b'{"status":200,"status":301,"headers":{}}',
            b'{"status":200,"headers":{},"private-field":true}',
            b"[]", b"\xff", b" " * (2 * 1024 * 1024 + 1),
        ):
            result = subprocess.run([sys.executable, "-ISB", str(CHECKER)],
                                    input=raw, capture_output=True)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(json.loads(result.stdout)["error"], "invalid_input")
            self.assertFalse(result.stderr)


if __name__ == "__main__":
    unittest.main()
