"""Test Nessus host/run attribution and projection through the public checker CLI."""
import json
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from xml.sax.saxutils import escape


ROOT = Path(__file__).resolve().parents[1]
START = "Wed Nov 18 13:45:00 2026"
SCOPE = {"asset": "demo-web", "run": "scan-07", "ref": "capture-07",
         "report_name": "Weekly OS", "host_name": "selected", "host_start": START,
         "direct_os_scan_verified": True, "coverage_records_complete": True}


def item(flag, plugin="19506"):
    return (f'<ReportItem pluginID="{plugin}"><plugin_output>Scan information\n'
            f'Credentialed checks : {escape(flag)}\n</plugin_output></ReportItem>')


def host(items, name="selected", start=START):
    return (f'<ReportHost name="{name}"><HostProperties><tag name="HOST_START">{start}</tag>'
            f'</HostProperties>{items}</ReportHost>')


def report(hosts, name="Weekly OS"):
    return f'<Report name="{name}">{hosts}</Report>'


def xml(*parts):
    return "<NessusClientData_v2>" + "".join(parts) + "</NessusClientData_v2>"


class CoverageTests(unittest.TestCase):
    def run_cli(self, raw, *args, code=0):
        result = subprocess.run([sys.executable, "-ISB", str(ROOT / "scripts/check.py"), *args],
                                input=raw, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, code, (result.stdout, result.stderr))
        self.assertEqual(result.stderr, b"")
        return json.loads(result.stdout)

    def check(self, document, **scope):
        return self.run_cli(json.dumps({**SCOPE, **scope, "xml": document}).encode())

    def test_fixtures(self):
        for name, expected in (("gap", "reported_no"), ("pass", "reported_yes"), ("unknown", "unknown")):
            with self.subTest(name=name):
                row = self.run_cli((ROOT / "examples" / f"{name}.json").read_bytes())
                self.assertEqual(row["status"], expected)
                self.assertEqual(row["plugin_id"], 19506)

    def test_native_flag_spellings_and_unrecognized_values(self):
        for value in ("yes", "yes, as 'service user' via ssh", "yes as demo\\account via SMB",
                      "yes, via ssh", "YES, as 'demo', via smb"):
            with self.subTest(value=value):
                self.assertEqual(self.check(xml(report(host(item(value)))))["status"], "reported_yes")
        for value, expected in (("No", "reported_no"), ("yes, via HTTPS", "unknown"), ("yes-ish", "unknown"),
                                ("yes as user via ftp", "unknown"), ("not established", "unknown"),
                                ("yes\nCredentialed checks : no", "unknown"), ("yes\n***TRUNCATED***", "unknown")):
            with self.subTest(value=value):
                self.assertEqual(self.check(xml(report(host(item(value)))))["status"], expected)

    def test_login_and_os_assessment_evidence(self):
        login = item("yes", "141118")
        self.assertEqual(self.check(xml(report(host(login))))["status"], "unknown")
        self.assertEqual(self.check(xml(report(host(item("no") + login))))["status"], "reported_no")
        for plugin in ("21745", "110695"):
            failure = f'<ReportItem pluginID="{plugin}"/>'
            with self.subTest(plugin=plugin):
                self.assertEqual(self.check(xml(report(host(item("yes") + failure))))["status"], "unknown")
                self.assertEqual(self.check(xml(report(host(item("yes")) + host(failure, "other"))))["status"],
                                 "reported_yes")

    def test_host_report_run_and_native_nesting(self):
        yes, no = item("yes"), item("no")
        self.assertEqual(self.check(xml(report(host(yes, "other") + host(no)), report(host(yes), "Older")))["status"],
                         "reported_no")
        for document in (
            xml(report(host(yes, "other"))), xml(report(host(yes, start="Mon Nov 16 13:45:00 2026"))),
            xml(report(host(yes), "Other")), xml(report(host(yes) + host(no))),
            xml(report(host(yes)), report(host(no))), xml(report(host(yes + no))),
            xml("<Policy>" + report(host(yes)) + "</Policy>"),
            xml(report(host("<other>" + yes + "</other>"))), xml(report(host(yes.replace("pluginID", "pluginName")))),
            xml(report(host(yes.replace("yes\n", "<other>yes</other>\n")))),
            xml(report(host(yes.replace("<plugin_output>", "<plugin_output/><plugin_output>")))),
        ):
            with self.subTest(document=document):
                self.assertEqual(self.check(document)["status"], "unknown")

    def test_missing_scope_and_filtered_evidence(self):
        document = xml(report(host(item("yes"))))
        for key in SCOPE:
            scope = {k: v for k, v in SCOPE.items() if k != key}
            with self.subTest(missing=key):
                row = self.run_cli(json.dumps({**scope, "xml": document}).encode())
                self.assertEqual(row["status"], "unknown")
        for key in ("direct_os_scan_verified", "coverage_records_complete"):
            self.assertEqual(self.check(document, **{key: False})["status"], "unknown")
        self.assertEqual(self.run_cli(json.dumps(SCOPE).encode())["status"], "unknown")

    def test_file_and_inline_match_and_project_only_scoped_data(self):
        document = xml("<Policy><Preferences>private-policy-test</Preferences></Policy>",
                       report(host(item("yes, as 'private-account-test' via ssh")) + host(item("no"), "unrelated")))
        row = self.check(document)
        self.assertEqual(row["status"], "reported_yes")
        self.assertEqual(row["evidence_ref"], "capture-07")
        for private in ("private-policy-test", "private-account-test", "unrelated", "Weekly OS", START):
            self.assertNotIn(private, json.dumps(row))
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "synthetic.nessus"
            path.write_bytes(document.encode())
            self.assertEqual(row, self.run_cli(json.dumps(SCOPE).encode(), "--xml-file", str(path)))
            both = json.dumps({**SCOPE, "xml": document}).encode()
            self.assertEqual(self.run_cli(both, "--xml-file", str(path), code=2)["error"], "invalid_input")

    def test_bad_input_has_only_a_controlled_json_error(self):
        nested = "<a>" * 65 + "</a>" * 65
        for raw in (b"[]", b'{"ref":"a","ref":"b"}', b'{"xml":NaN}', b'{"direct_os_scan_verified":1}',
                    b'{"coverage_records_complete":"true"}', b'{"xml":"<invalid"}',
                    b'{"xml":"<NessusClientData_v2 xmlns=\\"unrelated\\"/>"}',
                    json.dumps({"xml": "<!DOCTYPE NessusClientData_v2>" + xml()}).encode(),
                    json.dumps({"xml": xml(nested)}).encode()):
            with self.subTest(raw=raw[:70]):
                self.assertEqual(self.run_cli(raw, code=2)["error"], "invalid_input")
        with TemporaryDirectory() as tmp:
            file = Path(tmp) / "large.nessus"
            with file.open("wb") as stream:
                stream.truncate(8 * 1024 * 1024 + 1)
            self.assertEqual(self.run_cli(b"{}", "--xml-file", str(file), code=2)["error"], "invalid_input")


if __name__ == "__main__":
    unittest.main()
