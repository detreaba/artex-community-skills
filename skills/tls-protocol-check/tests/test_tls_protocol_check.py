"""Offline regressions for the TLS protocol-policy check.

Exercises the verdict logic in ``check.py`` (the examples plus the edge cases
the design calls out) and the input guards in ``observe.py``. No test opens a
socket. Python 3.9 grammar, standard library only.
"""
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
EXAMPLES = ROOT / "examples"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


check = _load("tls_check", SCRIPTS / "check.py")
observe = _load("tls_observe", SCRIPTS / "observe.py")


def _record(must_refuse, must_accept, attempts, control_class="negotiated"):
    control = {"class": control_class,
               "negotiated": "TLSv1.3" if control_class == "negotiated" else None,
               "reason": None}
    return {
        "skill": "tls-protocol-check",
        "observation_version": 1,
        "authorization_ref": "unit-test",
        "target": {"host": "127.0.0.1", "port": 8443, "sni": "fixture.local", "address": "127.0.0.1"},
        "policy": {"must_refuse": must_refuse, "must_accept": must_accept},
        "attempts": attempts,
        "control": control,
    }


def _att(version, cls, **kw):
    base = {"version": version, "class": cls, "reason": kw.get("reason"),
            "negotiated": kw.get("negotiated"), "cert_sha256": kw.get("cert_sha256"),
            "notes": kw.get("notes", [])}
    return base


class ExampleVerdicts(unittest.TestCase):
    def _overall(self, name):
        with (EXAMPLES / name).open(encoding="utf-8") as handle:
            return check.evaluate(json.load(handle))["overall"]

    def test_gap_example(self):
        self.assertEqual(self._overall("gap.json"), "gap")

    def test_pass_example(self):
        self.assertEqual(self._overall("pass.json"), "pass")

    def test_unknown_example(self):
        self.assertEqual(self._overall("unknown.json"), "unknown")


class VerdictRules(unittest.TestCase):
    def test_must_refuse_negotiated_is_gap(self):
        rec = _record(["1.0"], ["1.2"],
                      [_att("1.0", "negotiated", negotiated="TLSv1"),
                       _att("1.2", "negotiated", negotiated="TLSv1.2")])
        out = check.evaluate(rec)
        self.assertEqual(out["per_version"]["1.0"]["verdict"], "gap")
        self.assertEqual(out["overall"], "gap")

    def test_must_accept_negotiated_is_pass(self):
        rec = _record(["1.0"], ["1.2"],
                      [_att("1.0", "version_refused", reason="TLSV1_ALERT_PROTOCOL_VERSION"),
                       _att("1.2", "negotiated", negotiated="TLSv1.2")])
        out = check.evaluate(rec)
        self.assertEqual(out["per_version"]["1.2"]["verdict"], "pass")
        self.assertEqual(out["per_version"]["1.0"]["verdict"], "pass")
        self.assertEqual(out["overall"], "pass")

    def test_version_refused_without_completed_run_is_unknown(self):
        # Nothing negotiated anywhere -> cannot distinguish a policy refusal
        # from a dead/filtered endpoint -> fail closed to unknown.
        rec = _record(["1.0"], ["1.2"],
                      [_att("1.0", "version_refused", reason="TLSV1_ALERT_PROTOCOL_VERSION"),
                       _att("1.2", "closed", reason="UNEXPECTED_EOF_WHILE_READING")],
                      control_class="closed")
        out = check.evaluate(rec)
        self.assertEqual(out["per_version"]["1.0"]["verdict"], "unknown")
        self.assertEqual(out["per_version"]["1.2"]["verdict"], "unknown")
        self.assertEqual(out["overall"], "unknown")

    def test_must_accept_refused_with_completed_run_is_gap(self):
        rec = _record([], ["1.3"],
                      [_att("1.3", "version_refused", reason="TLSV1_ALERT_PROTOCOL_VERSION")],
                      control_class="negotiated")
        out = check.evaluate(rec)
        self.assertEqual(out["per_version"]["1.3"]["verdict"], "gap")
        self.assertEqual(out["overall"], "gap")

    def test_other_alert_is_unknown(self):
        rec = _record(["1.0"], ["1.2"],
                      [_att("1.0", "other_alert", reason="TLSV1_UNRECOGNIZED_NAME"),
                       _att("1.2", "negotiated", negotiated="TLSv1.2")])
        out = check.evaluate(rec)
        self.assertEqual(out["per_version"]["1.0"]["verdict"], "unknown")

    def test_missing_attempt_is_unknown(self):
        rec = _record(["1.0", "1.1"], ["1.2"],
                      [_att("1.0", "version_refused", reason="TLSV1_ALERT_PROTOCOL_VERSION"),
                       _att("1.2", "negotiated", negotiated="TLSv1.2")])
        out = check.evaluate(rec)
        self.assertEqual(out["per_version"]["1.1"]["verdict"], "unknown")

    def test_run_completed_by_control_only(self):
        rec = _record(["1.0"], [],
                      [_att("1.0", "version_refused", reason="TLSV1_ALERT_PROTOCOL_VERSION")],
                      control_class="negotiated")
        out = check.evaluate(rec)
        self.assertEqual(out["per_version"]["1.0"]["verdict"], "pass")

    def test_error_record_is_unknown(self):
        out = check.evaluate({"error": "invalid_input", "reason": "authorization_ref is required"})
        self.assertEqual(out["overall"], "unknown")

    def test_empty_policy_is_unknown(self):
        out = check.evaluate(_record([], [], []))
        self.assertEqual(out["overall"], "unknown")


class OverlapAndFailClosed(unittest.TestCase):
    def test_overlap_negotiated_is_gap_not_pass(self):
        # A version in both lists must not let must_accept's pass overwrite
        # must_refuse's gap (the false-clean the verification caught).
        rec = _record(["1.0"], ["1.0"],
                      [_att("1.0", "negotiated", negotiated="TLSv1")],
                      control_class="negotiated")
        out = check.evaluate(rec)
        self.assertEqual(out["per_version"]["1.0"]["verdict"], "gap")
        self.assertEqual(out["overall"], "gap")

    def test_realistic_overlap_gap(self):
        rec = _record(["1.0", "1.1"], ["1.1", "1.2", "1.3"],
                      [_att("1.0", "version_refused", reason="TLSV1_ALERT_PROTOCOL_VERSION"),
                       _att("1.1", "negotiated", negotiated="TLSv1.1"),
                       _att("1.2", "negotiated", negotiated="TLSv1.2"),
                       _att("1.3", "negotiated", negotiated="TLSv1.3")])
        out = check.evaluate(rec)
        self.assertEqual(out["per_version"]["1.1"]["verdict"], "gap")
        self.assertEqual(out["overall"], "gap")

    def test_control_negotiated_must_refuse_is_gap(self):
        # F-TLS-1: the full-range control negotiated a must-refuse version, so the
        # server accepts it even though the single-version attempt was refused.
        rec = _record(["1.0", "1.1"], ["1.2", "1.3"],
                      [_att("1.0", "version_refused", reason="TLSV1_ALERT_PROTOCOL_VERSION"),
                       _att("1.1", "version_refused", reason="TLSV1_ALERT_PROTOCOL_VERSION"),
                       _att("1.2", "negotiated", negotiated="TLSv1.2"),
                       _att("1.3", "negotiated", negotiated="TLSv1.3")])
        rec["control"] = {"class": "negotiated", "negotiated": "TLSv1", "reason": None}
        out = check.evaluate(rec)
        self.assertEqual(out["per_version"]["1.0"]["verdict"], "gap")
        self.assertEqual(out["overall"], "gap")

    def test_control_negotiated_must_accept_unchanged(self):
        # The normal pass case: control negotiates a must-accept version.
        out = check.evaluate(_record(["1.0"], ["1.2"],
                             [_att("1.0", "version_refused", reason="TLSV1_ALERT_PROTOCOL_VERSION"),
                              _att("1.2", "negotiated", negotiated="TLSv1.2")],
                             control_class="negotiated"))
        self.assertEqual(out["overall"], "pass")

    def test_attempt_negotiated_must_refuse_version_is_gap(self):
        # F-TLS-2: a dedicated attempt's negotiated field records a must-refuse
        # version (a completed TLS 1.0 handshake), which must be a gap.
        rec = _record(["1.0", "1.1"], ["1.2", "1.3"],
                      [_att("1.0", "version_refused", reason="TLSV1_ALERT_PROTOCOL_VERSION"),
                       _att("1.1", "version_refused", reason="TLSV1_ALERT_PROTOCOL_VERSION"),
                       _att("1.2", "negotiated", negotiated="TLSv1"),
                       _att("1.3", "negotiated", negotiated="TLSv1.3")])
        out = check.evaluate(rec)
        self.assertEqual(out["overall"], "gap")
        self.assertEqual(out["per_version"]["1.0"]["verdict"], "gap")

    def test_accept_passes_only_if_exact_version_negotiated(self):
        # A must-accept attempt that completed on a different version is not a
        # confirmed pass for the listed version.
        rec = _record([], ["1.2", "1.3"],
                      [_att("1.2", "negotiated", negotiated="TLSv1.3"),
                       _att("1.3", "negotiated", negotiated="TLSv1.3")])
        out = check.evaluate(rec)
        self.assertEqual(out["per_version"]["1.2"]["verdict"], "unknown")
        self.assertEqual(out["overall"], "unknown")

    def test_non_list_policy_fields_fail_closed(self):
        out = check.evaluate({"policy": {"must_refuse": True, "must_accept": "1.2"},
                              "attempts": [_att("1.0", "negotiated", negotiated="TLSv1")],
                              "control": {"class": "negotiated"}})
        self.assertEqual(out["overall"], "unknown")

    def test_falsy_error_key_is_unknown(self):
        out = check.evaluate({"error": "", "policy": {"must_accept": ["1.2"]},
                              "attempts": [_att("1.2", "negotiated", negotiated="TLSv1.2")],
                              "control": {"class": "negotiated"}})
        self.assertEqual(out["overall"], "unknown")

    def test_malformed_inner_types_fail_closed(self):
        for payload in (b'{"attempts":[null],"policy":{"must_refuse":["1.0"]}}',
                        b'{"control":"negotiated","policy":{"must_accept":["1.2"]}}',
                        b'{"must_refuse":1.0}'):
            proc = subprocess.run([sys.executable, "-B", str(SCRIPTS / "check.py")],
                                  input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(proc.returncode, 0, proc.stderr.decode("utf-8", "replace"))
            self.assertEqual(json.loads(proc.stdout.decode("utf-8"))["overall"], "unknown")

    def test_deeply_nested_json_fail_closed(self):
        proc = subprocess.run([sys.executable, "-B", str(SCRIPTS / "check.py")],
                              input=b"[" * 100000, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode("utf-8", "replace"))
        self.assertEqual(json.loads(proc.stdout.decode("utf-8"))["overall"], "unknown")


class CheckCli(unittest.TestCase):
    def test_runs_as_script_on_example(self):
        proc = subprocess.run([sys.executable, "-B", str(SCRIPTS / "check.py")],
                              input=(EXAMPLES / "gap.json").read_bytes(),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode("utf-8", "replace"))
        self.assertEqual(json.loads(proc.stdout.decode("utf-8"))["overall"], "gap")

    def test_invalid_json_fails_closed(self):
        proc = subprocess.run([sys.executable, "-B", str(SCRIPTS / "check.py")],
                              input=b"{not json",
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(json.loads(proc.stdout.decode("utf-8"))["overall"], "unknown")


class ObserveGuards(unittest.TestCase):
    def test_requires_authorization_ref(self):
        _, err = observe._validate({"target": {"host": "127.0.0.1", "port": 8443},
                                    "policy": {"must_refuse": ["1.0"]}})
        self.assertIn("authorization_ref", err)

    def test_rejects_host_list(self):
        _, err = observe._validate({"authorization_ref": "x",
                                    "target": {"host": "a.example,b.example", "port": 443},
                                    "policy": {"must_refuse": ["1.0"]}})
        self.assertIn("one host", err)

    def test_rejects_wildcard_and_cidr(self):
        for host in ("*.example.com", "10.0.0.0/24"):
            _, err = observe._validate({"authorization_ref": "x",
                                        "target": {"host": host, "port": 443},
                                        "policy": {"must_refuse": ["1.0"]}})
            self.assertIsNotNone(err)

    def test_rejects_bad_port(self):
        for port in (0, 70000, "443", True):
            _, err = observe._validate({"authorization_ref": "x",
                                        "target": {"host": "127.0.0.1", "port": port},
                                        "policy": {"must_refuse": ["1.0"]}})
            self.assertIn("port", err)

    def test_rejects_unknown_version(self):
        _, err = observe._validate({"authorization_ref": "x",
                                    "target": {"host": "127.0.0.1", "port": 443},
                                    "policy": {"must_refuse": ["1.4"]}})
        self.assertIn("unknown TLS version", err)

    def test_rejects_hostname_pinned_address(self):
        # A hostname in `address` would let create_connection re-resolve and
        # fan out past the connection cap; only an IP literal is allowed.
        for addr in ("evil.example", "127.0.0.1 ", "10.0.0.0/24", ["127.0.0.1"], 4321):
            _, err = observe._validate({"authorization_ref": "x",
                                        "target": {"host": "127.0.0.1", "port": 443, "address": addr},
                                        "policy": {"must_refuse": ["1.0"]}})
            self.assertIsNotNone(err)
            self.assertIn("IP literal", err)

    def test_accepts_ip_pinned_address(self):
        for addr in ("203.0.113.5", "::1"):
            valid, err = observe._validate({"authorization_ref": "x",
                                            "target": {"host": "host.example", "port": 443, "address": addr},
                                            "policy": {"must_refuse": ["1.0"]}})
            self.assertIsNone(err, addr)
            self.assertIsNotNone(valid)

    def test_rejects_non_object_policy(self):
        _, err = observe._validate({"authorization_ref": "x",
                                    "target": {"host": "127.0.0.1", "port": 443},
                                    "policy": "must refuse everything"})
        self.assertIn("policy must be an object", err)

    def test_rejects_non_string_sni(self):
        _, err = observe._validate({"authorization_ref": "x",
                                    "target": {"host": "127.0.0.1", "port": 443, "sni": 1234},
                                    "policy": {"must_refuse": ["1.0"]}})
        self.assertIn("sni", err)

    def test_accepts_well_formed_request(self):
        valid, err = observe._validate({"authorization_ref": "ref",
                                        "target": {"host": "127.0.0.1", "port": 8443, "sni": "fixture.local"},
                                        "policy": {"must_refuse": ["1.0", "1.1"], "must_accept": ["1.2", "1.3"]}})
        self.assertIsNone(err)
        self.assertIsNotNone(valid)

    def test_invalid_input_main_emits_error_record(self):
        stdin = io.StringIO(json.dumps({"target": {"host": "127.0.0.1", "port": 443}}))
        out = io.StringIO()
        old_in, old_out = sys.stdin, sys.stdout
        try:
            sys.stdin, sys.stdout = stdin, out
            observe.main()
        finally:
            sys.stdin, sys.stdout = old_in, old_out
        record = json.loads(out.getvalue())
        self.assertEqual(record["error"], "invalid_input")


if __name__ == "__main__":
    unittest.main()
