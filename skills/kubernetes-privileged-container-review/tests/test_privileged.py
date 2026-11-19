import json
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]


def fixture(case):
    return json.loads((ROOT / "examples" / (case + ".json")).read_text())


def cli(raw):
    proc = subprocess.run([sys.executable, "-ISB", str(ROOT / "scripts/check.py")], input=raw,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
    return proc.returncode, json.loads(proc.stdout)


class PrivilegedTests(unittest.TestCase):
    def check(self, data):
        status, row = cli(json.dumps(data).encode())
        self.assertEqual(status, 0, row)
        self.assertEqual(row["standard_compliance"], "unknown")
        return row

    def test_published_examples_and_flag_defaults(self):
        for name in ("gap", "pass", "unknown"):
            self.assertEqual(self.check(fixture(name))["status"], name)
        row = self.check(fixture("pass"))
        self.assertEqual([(c["recorded_privileged"], c["effective_privileged"]) for c in row["containers"]],
                         [(False, False), (None, False)])
        data = fixture("pass")
        container = data["evidence"]["pod"]["spec"]["containers"][0]
        for security in (None, {}, {"privileged": None}):
            container["securityContext"] = security
            self.assertEqual(self.check(data)["status"], "pass")

    def test_positive_in_any_of_the_three_lists(self):
        for group in ("containers", "initContainers", "ephemeralContainers"):
            with self.subTest(group=group):
                data = fixture("pass")
                container = {"name": "observed-" + group.lower(), "securityContext": {"privileged": True}}
                data["evidence"]["pod"]["spec"].setdefault(group, []).append(container)
                row = self.check(data)
                self.assertEqual(row["status"], "gap")
                self.assertEqual([(r["list"], r["name"]) for r in row["containers"] if r["effective_privileged"]],
                                 [(group, container["name"])])

    def test_incomplete_evidence_allows_concrete_gap_only(self):
        data = fixture("gap")
        data["evidence"]["privilege_fields_complete"] = False
        row = self.check(data)
        self.assertEqual(row["status"], "gap")
        self.assertFalse(row["coverage_complete"])
        self.assertIsNone(row["containers"][1]["effective_privileged"])
        data = fixture("pass")
        del data["evidence"]["privilege_fields_complete"]
        self.assertEqual(self.check(data)["status"], "unknown")

    def test_missing_lists_and_required_regular_container(self):
        for group, value in (("containers", []), ("containers", None), ("initContainers", None),
                             ("ephemeralContainers", None)):
            with self.subTest(group=group, value=value):
                data = fixture("pass")
                data["evidence"]["pod"]["spec"][group] = value
                self.assertEqual(self.check(data)["status"], "unknown")
        data = fixture("pass")
        del data["evidence"]["pod"]["spec"]["containers"]
        self.assertEqual(self.check(data)["status"], "unknown")

    def test_stale_recreated_wrong_cluster_and_missing_identity(self):
        for field, value in (("cluster", "different-cluster"), ("namespace", "other"), ("name", "another-pod"),
                             ("uid", "recreated-pod"), ("resourceVersion", "8241"), ("uid", None)):
            with self.subTest(field=field, value=value):
                data = fixture("gap")
                data["scope"][field] = value
                row = self.check(data)
                self.assertEqual((row["status"], row["containers"], row["evidence_ref"]), ("unknown", [], None))

    def test_windows_unspecified_os_templates_and_unverified_admission(self):
        for os_value in ({"name": "windows"}, {}, None):
            data = fixture("gap")
            data["evidence"]["pod"]["spec"]["os"] = os_value
            self.assertEqual(self.check(data)["status"], "unknown")
        for source in ("template", "webhook-allowed", "server-dry-run"):
            data = fixture("pass")
            data["evidence"]["source"] = source
            self.assertEqual(self.check(data)["status"], "unknown")
        data = fixture("gap")
        data["evidence"]["pod"].update(apiVersion="apps/v1", kind="Deployment")
        self.assertEqual(self.check(data)["status"], "unknown")
        data = fixture("pass")
        data["evidence"]["source"] = "persisted-admission-response"
        self.assertEqual(self.check(data)["status"], "pass")

    def test_extra_native_fields_do_not_leak_or_change_this_control(self):
        data = fixture("pass")
        container = data["evidence"]["pod"]["spec"]["containers"][0]
        container.update(env=[{"name": "PLACEHOLDER", "value": "sample-private-value"}])
        container["securityContext"]["allowPrivilegeEscalation"] = True
        row = self.check(data)
        self.assertEqual(row["status"], "pass")
        self.assertNotIn("sample-private-value", json.dumps(row))

    def test_malformed_and_duplicate_records(self):
        invalid = [b"[]", b" " * (1024 * 1024 + 1), b'{"scope":{},"scope":{}}']
        for c in ([{"name": "web", "securityContext": {"privileged": "false"}}],
                  [{"name": "web", "securityContext": []}], [{"name": "prepare"}],
                  [{"image": "training"}], ["web"], {}):
            data = fixture("pass")
            data["evidence"]["pod"]["spec"]["containers"] = c
            invalid.append(json.dumps(data).encode())
        data = fixture("pass")
        data["evidence"]["privilege_fields_complete"] = 1
        invalid.append(json.dumps(data).encode())
        for raw in invalid:
            with self.subTest(length=len(raw)):
                self.assertEqual(cli(raw), (2, {"error": "invalid_input"}))
