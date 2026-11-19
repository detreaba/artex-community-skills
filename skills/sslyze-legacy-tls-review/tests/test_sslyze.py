import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]


def fixture(name="pass"):
    return json.loads((ROOT / "examples" / f"{name}.json").read_bytes())


def invoke(data):
    raw = data if isinstance(data, bytes) else json.dumps(data).encode()
    run = subprocess.run([sys.executable, "-ISB", str(ROOT / "scripts/check.py")],
                         input=raw, capture_output=True, timeout=10)
    if run.stderr:
        raise AssertionError(run.stderr)
    return run.returncode, json.loads(run.stdout)


class SslyzeTests(unittest.TestCase):
    def check(self, data):
        code, result = invoke(data)
        self.assertEqual(code, 0, result)
        return result

    def test_native_examples_and_fingerprint(self):
        for status, coverage in (("gap", "complete_for_reported_endpoints"),
                                 ("pass", "complete_for_reported_endpoints"), ("unknown", "incomplete")):
            with self.subTest(status=status):
                raw = (ROOT / "examples" / f"{status}.json").read_bytes()
                result = self.check(raw)
                self.assertEqual((result["status"], result["coverage"]), (status, coverage))
                self.assertEqual(result["report_sha256"], hashlib.sha256(raw).hexdigest())
                row = result["endpoints"][0]
                self.assertEqual((row["hostname"], row["ip"], row["port"], row["sni"]),
                                 ("site.example", "192.0.2.25", 443, "site.example"))

    def test_mixed_known_gap_and_failed_endpoint(self):
        data = fixture("gap")
        failed = copy.deepcopy(data["server_scan_results"][0])
        failed.update(uuid="00000000-0000-4000-8000-000000000002", connectivity_status="ERROR",
                      connectivity_result=None, scan_status="ERROR_NO_CONNECTIVITY", scan_result=None)
        data["server_scan_results"].append(failed)
        row = self.check(data)
        self.assertEqual((row["status"], row["coverage"], len(row["endpoints"])), ("gap", "incomplete", 2))
        self.assertEqual(row["endpoints"][1]["protocols"]["TLS_1_1"]["status"], "unknown")

    def test_invalid_targets_and_empty_report(self):
        data = fixture()
        data["invalid_server_strings"] = [{"server_string": "private intake value", "error_message": "private trace"}]
        result = self.check(data)
        self.assertEqual((result["status"], result["invalid_target_count"]), ("unknown", 1))
        self.assertNotIn("private", json.dumps(result))
        data.update(server_scan_results=[], invalid_server_strings=[])
        self.assertEqual(self.check(data)["status"], "unknown")

    def test_missing_or_contradictory_protocol_results(self):
        for field, value in (("accepted_cipher_suites", None), ("is_tls_version_supported", True),
                             ("rejected_cipher_suites", []), ("tls_version_used", "TLS_1_2")):
            with self.subTest(field=field):
                data = fixture()
                attempt = data["server_scan_results"][0]["scan_result"]["tls_1_0_cipher_suites"]
                attempt["result"][field] = value
                row = self.check(data)
                self.assertEqual(row["status"], "unknown")
                self.assertEqual(row["endpoints"][0]["protocols"]["TLS_1_1"]["status"], "pass")
        data = fixture()
        data["server_scan_results"][0]["connectivity_result"]["highest_tls_version_supported"] = "TLS_1_0"
        self.assertEqual(self.check(data)["status"], "unknown")

    def test_timeout_error_or_unscheduled_are_not_pass(self):
        for kind in ("timeout", "ambiguous", "ERROR", "NOT_SCHEDULED"):
            with self.subTest(kind=kind):
                data = fixture()
                attempt = data["server_scan_results"][0]["scan_result"]["tls_1_0_cipher_suites"]
                if kind in ("timeout", "ambiguous"):
                    msg = "TLS handshake with server timed out" if kind == "timeout" else "TLS alert: handshake failure"
                    attempt["result"]["rejected_cipher_suites"][0]["error_message"] = msg
                else:
                    attempt.update(status=kind, result=None)
                self.assertEqual(self.check(data)["status"], "unknown")

    def test_connection_scope_and_version_gates(self):
        for group, key, value in (("server_location", "connection_type", "VIA_HTTP_PROXY"),
                                  ("network_configuration", "tls_opportunistic_encryption", "SMTP"),
                                  ("network_configuration", "tls_client_auth_credentials", {"key_password": "secret"}),
                                  ("network_configuration", "tls_server_name_indication", ""),
                                  ("server_location", "port", False)):
            with self.subTest(key=key):
                data = fixture("gap")
                data["server_scan_results"][0][group][key] = value
                row = self.check(data)
                self.assertEqual(row["status"], "unknown")
                self.assertNotIn("secret", json.dumps(row))
        data = fixture("gap")
        data["sslyze_version"] = "7.0.0"
        self.assertEqual(self.check(data)["status"], "unknown")

    def test_malformed_input_and_reversed_time(self):
        data = fixture()
        data["date_scans_completed"] = "2025-01-01T00:00:00Z"
        for bad in (data, b'{"sslyze_version":"6.1.0","sslyze_version":"6.3.1"}', b"["):
            code, out = invoke(bad)
            self.assertEqual((code, out["error"]), (2, "invalid_input"))
