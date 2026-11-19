import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def fixture(name="gap"):
    return json.loads((ROOT / "examples" / (name + ".json")).read_text())


def site(data):
    return data["evidence"]["document"]["site"][0]


def cli(data, *args):
    raw = data if isinstance(data, bytes) else json.dumps(data).encode()
    result = subprocess.run([sys.executable, "-ISB", str(ROOT / "scripts/check.py"), *args],
                            input=raw, capture_output=True, timeout=5)
    return result.returncode, json.loads(result.stdout)


class AlertTests(unittest.TestCase):
    def check(self, data):
        code, row = cli(data)
        self.assertEqual(code, 0, row)
        return row

    def test_examples(self):
        for name in ("gap", "pass", "unknown"):
            with self.subTest(name=name):
                row = self.check(fixture(name))
                self.assertEqual((row["status"], row["site_exposure"]), (name, "unknown"))
        row = self.check(fixture())
        self.assertEqual(row["groups"], [{"rule_id": 900001, "alert_ref": "900001-1", "risk": "medium",
                                         "confidence": "medium", "reported_instances": 1, "meets_threshold": True}])

    def test_risk_and_confidence_are_independent_required_minimums(self):
        for risk, conf, expected in ((3, 0, "pass"), (3, 1, "pass"), (1, 4, "pass"), (2, 2, "gap"), (3, 4, "gap")):
            data = fixture()
            site(data)["alerts"][0].update(riskcode=risk, confidence=conf)
            with self.subTest(risk=risk, confidence=conf):
                row = self.check(data)
                self.assertEqual((row["status"], row["site_exposure"]), (expected, "unknown"))
                if conf == 4:
                    self.assertEqual(row["groups"][0]["confidence"], "user_confirmed")

    def test_empty_and_partial_exports_cannot_pass(self):
        for risk, expected in (("1", "unknown"), ("3", "gap")):
            data = fixture()
            data["evidence"]["export_scope"] = "filtered"
            site(data)["alerts"][0]["riskcode"] = risk
            row = self.check(data)
            self.assertEqual((row["status"], row["export_coverage"]), (expected, "partial"))
        data = fixture("unknown")
        self.assertEqual(self.check(data)["status"], "unknown")
        del site(data)["alerts"]
        self.assertEqual(self.check(data)["status"], "unknown")

    def test_incomplete_group_preserves_a_valid_qualifying_lead(self):
        data = fixture()
        bad = copy.deepcopy(site(data)["alerts"][0])
        bad["count"] = "8"
        site(data)["alerts"].append(bad)
        row = self.check(data)
        self.assertEqual((row["status"], row["export_coverage"], row["incomplete_groups"], row["qualifying_groups"]),
                         ("gap", "partial", 1, 1))

    def test_missing_instances_invalid_ratings_and_cross_origin_evidence(self):
        for updates in ({"count": True}, {"count": "0", "instances": []}, {"confidence": "5"}, {"riskcode": "01"},
                        {"pluginid": "custom text"}, {"instances": [{}]},
                        {"instances": [{"uri": "https://another.invalid/path"}]},
                        {"instances": [{"uri": "https://training.example.invalid:8443/example"}]},
                        {"instances": [{"uri": "https://someone@training.example.invalid/example"}]}):
            with self.subTest(fields=tuple(updates)):
                data = fixture()
                site(data)["alerts"][0].update(updates)
                self.assertEqual(self.check(data)["status"], "unknown")

    def test_origin_binding_including_default_ports_and_legacy_report(self):
        data = fixture()
        data["policy"]["origin"] = "https://TRAINING.example.invalid:443/"
        del data["evidence"]["document"]["@programName"]
        self.assertEqual(self.check(data)["status"], "gap")
        for attr, value in (("@host", "elsewhere.invalid"), ("@port", "8000"), ("@ssl", "false"),
                            ("@ssl", 1), ("@name", "https://training.example.invalid/other")):
            change = copy.deepcopy(data)
            site(change)[attr] = value
            self.assertEqual(self.check(change)["status"], "unknown")
        data["evidence"]["document"]["site"].append(copy.deepcopy(site(data)))
        self.assertEqual(self.check(data)["status"], "unknown")

    def test_another_sites_alerts_never_influence_selected_report(self):
        data = fixture("pass")
        other = site(fixture("gap"))
        other["@host"] = "scope-2.invalid"
        other["@name"] = "https://scope-2.invalid"
        other["alerts"][0]["instances"][0]["uri"] = "https://scope-2.invalid/example"
        data["evidence"]["document"]["site"].append(other)
        row = self.check(data)
        self.assertEqual((row["status"], len(row["groups"])), ("pass", 1))

    def test_operator_scope_and_failed_runs(self):
        for key, value in (("build", "other-build"), ("asset", "other-asset"), ("ref", None),
                           ("run_status", None), ("run_status", "failed")):
            data = fixture()
            data["evidence"][key] = value
            self.assertEqual(self.check(data)["status"], "unknown")
        for key in ("min_risk", "min_confidence", "origin", "ref"):
            data = fixture()
            del data["policy"][key]
            self.assertEqual(self.check(data)["status"], "unknown")

    def test_sensitive_fields_are_absent_from_output(self):
        data = fixture()
        report = data["evidence"]["document"]
        secret = "private-training-marker"
        report["insights"] = {"sample": secret}
        alert = site(data)["alerts"][0]
        alert.update(alert=secret, alertRef=secret, name=secret, description=secret, evidence=secret)
        alert["instances"][0].update(uri="https://training.example.invalid/" + secret + "?query=" + secret,
                                     attack=secret, param=secret, requestHeader=secret, responseBody=secret)
        row = self.check(data)
        self.assertEqual((row["status"], row["groups"][0]["alert_ref"]), ("gap", None))
        for value in (secret, "training.example.invalid", "requestHeader", "?query", "https://"):
            self.assertNotIn(value, json.dumps(row))

    def test_malformed_files_and_size_limit(self):
        self.assertEqual(cli(b'{"evidence":{},"evidence":{}}')[0], 2)
        self.assertEqual(cli(b" " * (4 * 1024 * 1024 + 1))[0], 2)
        self.assertEqual(cli(b'[]')[0], 2)
        data = fixture()
        del data["evidence"]["document"]
        self.assertEqual(self.check(data)["status"], "unknown")

    def test_original_file_entry_point(self):
        data = fixture()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "saved.json"
            path.write_text(json.dumps(data["evidence"]["document"]))
            self.assertEqual(cli(data, "--report-file", str(path))[0], 2)
            data["evidence"].pop("document")
            code, row = cli(data, "--report-file", str(path))
            self.assertEqual((code, row["status"]), (0, "gap"))
            path.write_text('{"site":[],"site":[]}')
            self.assertEqual(cli(data, "--report-file", str(path))[0], 2)
