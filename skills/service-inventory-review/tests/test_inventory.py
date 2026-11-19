import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from xml.etree import ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]


def fixture(name="pass"):
    return json.loads((ROOT / "examples" / (name + ".json")).read_text())


def execute(data, *args):
    raw = data if isinstance(data, bytes) else json.dumps(data).encode()
    proc = subprocess.run([sys.executable, "-ISB", str(ROOT / "scripts/check.py"), *args],
                          input=raw, capture_output=True, timeout=5)
    return proc.returncode, json.loads(proc.stdout)


def edited(change, name="pass"):
    data = fixture(name)
    tree = ET.fromstring(data["report"]["xml"])
    change(tree)
    data["report"]["xml"] = ET.tostring(tree, encoding="unicode")
    return data


class InventoryTests(unittest.TestCase):
    def check(self, data):
        code, result = execute(data)
        self.assertEqual(code, 0, result)
        return result

    def test_bundled_examples(self):
        for name in ("gap", "pass", "unknown"):
            with self.subTest(name=name):
                row = self.check(fixture(name))
                self.assertEqual(row["status"], name)
                self.assertEqual(row["finished_epoch"], 1795003205)
        self.assertEqual(self.check(fixture("gap"))["checks"][-1],
                         {"endpoint": "tcp/8443", "open_approved": False, "observed_state": "open", "status": "gap"})
        self.assertEqual(self.check(fixture())["checks"][1]["observed_state"], "closed")
        self.assertTrue(self.check(fixture("unknown"))["unresolved_aggregate"])

    def test_asset_address_deployment_and_vantage_are_bound_to_policy(self):
        for key, other in (("asset", "other"), ("deployment", "earlier"), ("address", "192.0.2.19"),
                           ("vantage", "internal")):
            with self.subTest(key=key):
                data = fixture()
                data["report"][key] = other
                result = self.check(data)
                self.assertEqual((result["status"], result["checks"]), ("unknown", []))
        for key in ("required", "allowed_open", "ref"):
            data = fixture()
            data["policy"].pop(key)
            self.assertEqual(self.check(data)["status"], "unknown")
        data = fixture()
        data["policy"]["allowed_open"] = []
        self.assertEqual(self.check(data)["status"], "gap")

    def test_completed_job_and_one_live_match_are_required(self):
        changes = (
            lambda t: t.remove(t.find("runstats")),
            lambda t: t.find("runstats/finished").set("exit", "error"),
            lambda t: t.find("runstats/finished").attrib.pop("time"),
            lambda t: t.set("start", "1795010000"),
            lambda t: t.find("runstats/hosts").set("up", "0"),
            lambda t: t.find("host/status").set("state", "down"),
            lambda t: t.find("host").set("timedout", "true"),
            lambda t: t.find("host/address").set("addr", "192.0.2.23"),
            lambda t: t.append(t.find("host")),
            lambda t: ET.SubElement(t.find("host"), "address", addr="2001:db8::1", addrtype="ipv6"),
        )
        for change in changes:
            self.assertEqual(self.check(edited(change))["status"], "unknown")

    def test_other_hosts_and_service_labels_are_never_returned(self):
        def change(tree):
            other = ET.fromstring(ET.tostring(tree.find("host")))
            other.find("address").set("addr", "192.0.2.23")
            other.find("ports/port").set("portid", "23")
            tree.append(other)
            ET.SubElement(tree.find("host/ports/port"), "service", name="private-service", product="sensitive")
        result = self.check(edited(change))
        self.assertEqual(result["status"], "pass")
        for value in ("192.0.2.23", "private-service", "sensitive", "tcp/23"):
            self.assertNotIn(value, json.dumps(result))

    def test_ambiguous_states_and_missing_explicit_ports_are_unknown(self):
        for state in ("filtered", "open|filtered", "closed|filtered", "unfiltered", "private-label"):
            data = edited(lambda t: t.find("host/ports/port/state").set("state", state))
            row = self.check(data)
            self.assertEqual((row["status"], row["coverage"]), ("unknown", "partial"))
            self.assertNotIn("private-label", json.dumps(row))
        data = edited(lambda t: t.find("host/ports/extraports/extrareasons").attrib.pop("ports"))
        row = self.check(data)
        self.assertEqual(row["checks"][1]["observed_state"], "unobserved")
        self.assertEqual(row["status"], "unknown")

    def test_gap_survives_partial_coverage(self):
        data = fixture("gap")
        data["policy"]["required"].append("udp/443")
        row = self.check(data)
        self.assertEqual((row["status"], row["coverage"]), ("gap", "partial"))
        self.assertEqual(row["checks"][-1]["status"], "unknown")

    def test_protocol_and_explicit_grouped_ranges(self):
        def change(tree):
            group = tree.find("host/ports/extraports")
            group.set("count", "3")
            group.set("state", "open")
            reason = group.find("extrareasons")
            reason.attrib.update({"ports": "8079-8080,8082", "count": "3", "proto": "udp"})
        data = edited(change)
        row = self.check(data)
        gaps = {item["endpoint"] for item in row["checks"] if item["status"] == "gap"}
        self.assertEqual(gaps, {"udp/8079", "udp/8080", "udp/8082"})
        self.assertEqual(row["coverage"], "partial")
        data = edited(lambda t: t.find("host/ports/extraports/extrareasons").set("ports", "8080,8080"))
        self.assertEqual(execute(data)[0], 2)

    def test_aggregation_explicitly_scoped_to_sctp_does_not_change_tcp_review(self):
        def change(tree):
            group = ET.SubElement(tree.find("host/ports"), "extraports", state="filtered", count="2")
            ET.SubElement(group, "extrareasons", reason="no-responses", count="2", proto="sctp")
        self.assertEqual(self.check(edited(change))["status"], "pass")

    def test_ipv6_text_can_differ_and_approved_port_can_be_closed(self):
        def change(tree):
            tree.find("host/address").attrib.update(addrtype="ipv6", addr="2001:db8::2")
            tree.find("host/ports/port/state").set("state", "closed")
        data = edited(change)
        data["policy"]["address"] = "2001:db8:0:0:0:0:0:2"
        data["report"]["address"] = "2001:db8::2"
        row = self.check(data)
        self.assertEqual((row["status"], row["address"]), ("pass", "2001:db8::2"))

    def test_conflicting_or_unnamed_open_states_prevent_a_clean_result(self):
        def conflict(tree):
            ports = tree.find("host/ports")
            copy = ET.fromstring(ET.tostring(ports.find("port")))
            copy.find("state").set("state", "closed")
            ports.append(copy)
        row = self.check(edited(conflict))
        self.assertEqual((row["status"], row["checks"][0]["observed_state"]), ("unknown", "conflicting"))
        def anonymous(tree):
            ET.SubElement(tree.find("host/ports"), "extraports", state="open", count="2")
        row = self.check(edited(anonymous))
        self.assertEqual((row["status"], row["unresolved_aggregate"]), ("unknown", True))

    def test_xml_security_and_limits(self):
        for decl in ('<!DOCTYPE nmaprun [<!ENTITY x "unsafe">]>', '<!DOCTYPE nmaprun SYSTEM "private.dtd">',
                     '<!DOCTYPE nmaprun PUBLIC "author" "remote.dtd">'):
            data = fixture()
            data["report"]["xml"] = data["report"]["xml"].replace("<!DOCTYPE nmaprun>", decl)
            self.assertEqual(execute(data)[0], 2)
        for xml in ("<unclosed", "<x>" * 70 + "</x>" * 70, "x" * (2 * 1024 * 1024 + 1)):
            data = fixture()
            data["report"]["xml"] = xml
            self.assertEqual(execute(data)[0], 2)
        self.assertEqual(execute(b'{"report":{},"report":{}}')[0], 2)

    def test_raw_file_mode_and_one_artifact_per_review(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "record.xml"
            data = fixture()
            path.write_text(data["report"]["xml"])
            self.assertEqual(execute(data, "--xml-file", str(path))[0], 2)
            data["report"].pop("xml")
            code, row = execute(data, "--xml-file", str(path))
            self.assertEqual((code, row["status"]), (0, "pass"))
            self.assertEqual(execute(data, "--xml-file", str(path) + ".missing")[0], 2)
