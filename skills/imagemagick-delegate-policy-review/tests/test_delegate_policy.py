import json
from copy import deepcopy
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
CHECK = ROOT / "scripts" / "check.py"


def fixture(name="gap"):
    return json.loads((ROOT / "examples" / (name + ".json")).read_text())


def invoke(data, code=0):
    raw = data if isinstance(data, bytes) else json.dumps(data).encode()
    process = subprocess.run([sys.executable, "-ISB", str(CHECK)], input=raw,
                             capture_output=True, timeout=10, check=False)
    if process.returncode != code or process.stderr:
        raise AssertionError((process.returncode, process.stderr))
    return json.loads(process.stdout)


def rule(pattern, rights="none", domain="delegate"):
    return {"domain": domain, "pattern": pattern, "rights": rights}


def evaluate(*rules):
    data = fixture()
    data["export"]["rules"] = list(rules)
    value = invoke(data)
    return value["status"], value["named_execute"], value["uncertain_names"], value["other_execute"]


class DelegatePolicyTests(unittest.TestCase):
    def test_packaged_decisions(self):
        for name in ("gap", "pass", "unknown"):
            self.assertEqual(invoke(fixture(name))["status"], name)

    def test_default_and_non_delegate_rules(self):
        for rules in ([], [rule("*", "none", "coder")], [rule("*", "none", "module")]):
            self.assertEqual(evaluate(*rules), ("gap", [], [], "allowed"))

    def test_later_rules_shadow_earlier_rules(self):
        deny = rule("*")
        grant = rule("demo-render", "all")
        self.assertEqual(evaluate(deny, grant, rule("demo-render", "read | write")),
                         ("pass", [], [], "denied"))
        self.assertEqual(evaluate(grant, deny), ("pass", [], [], "denied"))
        self.assertEqual(evaluate(deny, grant), ("gap", ["demo-render"], [], "denied"))

    def test_plain_tag_spelling(self):
        self.assertEqual(evaluate(rule("*"), rule("Demo-Render", "Execute"), rule("demo-render")),
                         ("gap", ["Demo-Render"], [], "denied"))

    def test_opaque_pattern_cannot_create_a_false_witness(self):
        self.assertEqual(evaluate(rule("*"), rule("demo-*", "execute")),
                         ("unknown", [], [], "unknown"))
        self.assertEqual(evaluate(rule("demo-*", "execute"), rule("*")),
                         ("pass", [], [], "denied"))
        self.assertEqual(evaluate(rule("*"), rule("demo-*", "read")),
                         ("pass", [], [], "denied"))

    def test_partial_results_with_a_definite_later_grant(self):
        self.assertEqual(evaluate(rule("*"), rule(None, "execute"), rule("demo-preview", "all")),
                         ("gap", ["demo-preview"], [], "unknown"))
        self.assertEqual(evaluate(rule("*"), rule("demo-preview", "execute"), rule(None)),
                         ("unknown", [], ["demo-preview"], "denied"))

    def test_opaque_rights_and_domains(self):
        for r in (rule("demo", "redacted"), rule("demo", "execute", None),
                  rule("demo", "execute", "unrecognized")):
            self.assertEqual(evaluate(rule("*"), r), ("unknown", [], ["demo"], "denied"))
        self.assertEqual(evaluate({"domain":"delegate"}, rule("*")), ("pass", [], [], "denied"))

    def test_one_named_deny_leaves_the_default(self):
        self.assertEqual(evaluate(rule("demo")), ("gap", [], [], "allowed"))

    def test_origin_and_worker_identity(self):
        for field, value, reason in (("worker", "second", "worker_build_mismatch"),
                                     ("build", "second", "worker_build_mismatch"),
                                     ("build", None, "worker_evidence_missing"),
                                     ("version_ref", None, "unverified_build"),
                                     ("product", "other", "unverified_build"),
                                     ("origin", "downstream", "unverified_build"),
                                     ("ref", None, "worker_evidence_missing")):
            data = fixture()
            data["export"][field] = value
            got = invoke(data)
            self.assertEqual((got["status"], got["reason"], got["other_execute"]),
                             ("unknown", reason, "unassessed"))
        data = fixture()
        data["export"]["origin"] = "upstream_equivalent"
        self.assertEqual(invoke(data)["status"], "gap")

    def test_redacted_ids_and_refs_cannot_establish_identity(self):
        for field in ("build", "ref", "version_ref"):
            data = fixture("pass")
            data["export"][field] = "REDACTED"
            if field == "build":
                data["worker"]["build"] = "REDACTED"
            got = invoke(data)
            self.assertEqual((got["status"], got["other_execute"]), ("unknown", "unassessed"))

    def test_repeated_redactions_cannot_cancel_each_other(self):
        self.assertEqual(evaluate(rule("*"), rule("redacted", "execute"), rule("REDACTED")),
                         ("unknown", [], [], "unknown"))

    def test_listing_fragment_and_unavailable_rules(self):
        for kind in ("listing", "policy_file", None):
            data = fixture("pass")
            data["export"]["kind"] = kind
            self.assertEqual(invoke(data)["reason"], "effective_export_required")
        data = fixture("pass")
        del data["export"]["rules"]
        self.assertEqual(invoke(data)["reason"], "rules_unavailable")

    def test_coverage_requires_each_attestation(self):
        data = fixture("pass")
        for key in data["export"]["coverage"]:
            for absent in (None, False, 1):
                trial = deepcopy(data)
                trial["export"]["coverage"][key] = absent
                got = invoke(trial)
                self.assertEqual((got["status"], got["missing"], got["other_execute"]),
                                 ("unknown", [key], "unassessed"))

    def test_published_tag_boundaries(self):
        for tag in ("7.1.1-0", "7.1.1-41", "7.1.1-43", "7.1.1-47", "7.1.2-3",
                    "7.1.2-5", "7.1.2-19", "7.1.2-24", "7.1.2-36"):
            data = fixture("pass")
            data["export"]["version"] = tag
            self.assertEqual(invoke(data)["status"], "pass", tag)
        for tag in ("6.9.4-6", "7.0.1-7", "7.0.1-8", "7.1.1-42", "7.1.1-48",
                    "7.1.2-4", "7.1.2-20", "7.1.2-23", "7.1.2-37", "7.1.2-036",
                    "7.1.2-36-custom", None):
            data = fixture("pass")
            data["export"]["version"] = tag
            self.assertEqual(invoke(data)["reason"], "unsupported_release", tag)

    def test_invalid_json_shapes_and_limits(self):
        for raw in (b"{", b"[]", b'{"worker":1,"worker":2}', b'{"x":NaN}', b" " * (1024**2 + 1)):
            self.assertEqual(invoke(raw, 2), {"status": "invalid_input"})
        for rows in ({}, [None], [rule("*")] * 1025, [{"domain":"delegate", "when":True}]):
            data = fixture()
            data["export"]["rules"] = rows
            self.assertEqual(invoke(data, 2), {"status": "invalid_input"})


if __name__ == "__main__":
    unittest.main()
