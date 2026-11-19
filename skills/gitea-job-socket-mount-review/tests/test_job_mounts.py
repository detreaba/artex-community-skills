from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]


def example(key="pass"):
    return json.loads((ROOT / "examples" / (key + ".json")).read_text())


def run_check(data, code=0):
    raw = data if isinstance(data, bytes) else json.dumps(data).encode()
    p = subprocess.run([sys.executable, "-ISB", str(ROOT / "scripts/check.py")],
                       input=raw, capture_output=True, timeout=10)
    if p.returncode != code or p.stderr:
        raise AssertionError((p.returncode, p.stderr))
    return json.loads(p.stdout)


def parent():
    data = example()
    data["backing"]["mounts"][0]["canonical"] = "/fixture/control"
    return data


class JobMountTests(unittest.TestCase):
    def test_packaged_outcomes_and_refs(self):
        for key in ("gap", "pass", "unknown"):
            out = run_check(example(key))
            self.assertEqual(out["status"], key)
            self.assertEqual(out["refs"]["inspect"], "job-inspect-7")
            self.assertNotIn("/fixture", json.dumps(out))

    def test_read_only_and_partial_direct_mount(self):
        for rw in (False, True):
            data = example("gap")
            data["inspect"]["Mounts"][0]["RW"] = rw
            out = run_check(data)
            self.assertEqual((out["coverage"],out["gaps"]), ("partial", [{"row":1,"basis":"same_object"}]))

    def test_service_and_wrong_job_identity(self):
        for key, value in (("subject", "runner"), ("subject", "service"), ("kind", "job_manifest"),
                           ("os", "windows"), ("job", "other-job"), ("Id", "runner-container"),
                           ("daemon", "other"), ("runner", "other"), ("build", "other")):
            data = example("gap")
            data["inspect"][key] = value
            out = run_check(data)
            self.assertEqual((out["status"],out["coverage"],out["gaps"]), ("unknown","unassessed",[]),key)

    def test_socket_identity_and_refs(self):
        for key, value in (("socket_ref", "redacted"), ("socket_object", None), ("ref", "unknown"),
                           ("daemon", "other"), ("inspect_ref", "old"), ("socket_paths", []),
                           ("socket_paths", ["/"]), ("socket_paths", ["/fixture/../control"])):
            data = example("gap")
            data["policy"][key] = value
            self.assertEqual(run_check(data)["reason"], "socket_identity_unverified", key)
        data = example()
        data["inspect"]["Id"] = data["job"]["container"] = "REDACTED"
        self.assertEqual(run_check(data)["reason"], "job_identity_unverified")

    def test_parent_sibling_and_root(self):
        self.assertEqual(run_check(parent())["gaps"], [{"row":1,"basis":"parent_directory"}])
        self.assertEqual(run_check(example())["status"], "pass")
        data = parent()
        data["backing"]["mounts"][0]["canonical"] = "/"
        self.assertEqual(run_check(data)["status"], "gap")

    def test_complete_aliases_for_exclusion(self):
        data = example()
        data["policy"]["aliases_complete"] = False
        self.assertEqual(run_check(data)["unresolved"], [{"row":1,"reason":"socket_aliases_incomplete"}])
        data["policy"]["socket_paths"].append("/fixture/control-archive/alias.sock")
        self.assertEqual(run_check(data)["status"], "gap")

    def test_unfaithful_or_unobserved_parent(self):
        data = parent()
        data["backing"]["mounts"][0]["tree_complete"] = False
        self.assertEqual(run_check(data)["unresolved"], [{"row":1,"reason":"tree_unverified"}])
        for change in ({"coverage":"partial"}, {"total":2}):
            data = parent()
            data["inspect"].update(change)
            self.assertEqual(run_check(data)["unresolved"], [{"row":1,"reason":"parent_view_unverified"}])

    def test_nested_destination_needs_a_separate_parent_view(self):
        data = parent()
        name = data["inspect"]["Mounts"][0]["Destination"]
        nested = {"Type":"tmpfs","Source":"","Destination":name+"/nested","RW":True}
        data["inspect"]["Mounts"].append(nested)
        data["inspect"]["total"] = 2
        data["backing"]["mounts"].append({**nested,"kind":"private","tree_complete":True})
        out = run_check(data)
        self.assertEqual((out["status"],out["unresolved"]), ("unknown",[{"row":1,"reason":"parent_view_unverified"}]))

    def test_effective_file_object_after_a_pathname_change(self):
        data = example("gap")
        data["inspect"].update(coverage="complete",total=1)
        data["backing"]["mounts"][0]["object"] = "previous-file-object"
        self.assertEqual(run_check(data)["status"], "pass")
        del data["backing"]["mounts"][0]["object"]
        self.assertEqual(run_check(data)["status"], "unknown")

    def test_volume_backing_can_be_a_host_directory(self):
        data = example("unknown")
        m = data["inspect"]["Mounts"][0]
        data["backing"]["mounts"] = [{**m,"kind":"directory","canonical":"/fixture","tree_complete":True}]
        self.assertEqual(run_check(data)["gaps"], [{"row":1,"basis":"parent_directory"}])
        data["backing"]["mounts"][0]["canonical"] = "/fixture/unrelated"
        self.assertEqual(run_check(data)["status"], "pass")

    def test_tmpfs_and_unrecognized_mounts(self):
        data = example()
        m = {"Type":"tmpfs","Source":"","Destination":"/job/tmp","RW":True}
        data["inspect"]["Mounts"] = [m]
        data["backing"]["mounts"] = [{**m,"kind":"private","tree_complete":True}]
        self.assertEqual(run_check(data)["status"], "pass")
        data["inspect"]["Mounts"][0]["Type"] = "other"
        self.assertEqual(run_check(data)["unresolved"], [{"row":1,"reason":"unsupported_mount_type"}])

    def test_stale_duplicate_or_misbound_backing(self):
        for key in ("daemon","inspect_ref","ref"):
            data = example("gap")
            data["backing"][key] = None
            self.assertEqual(run_check(data)["status"], "unknown")
        for key in ("Type","Source","Destination"):
            data = example("gap")
            data["backing"]["mounts"][0][key] = "mismatch"
            self.assertEqual(run_check(data)["status"], "unknown")
        data = example("gap")
        data["backing"]["mounts"] *= 2
        self.assertEqual(run_check(data)["status"], "unknown")

    def test_complete_export_conflicting_with_same_capture_backing(self):
        data = example("gap")
        data["inspect"].update(Mounts=[], coverage="complete", total=0)
        self.assertEqual(run_check(data)["reason"], "contradictory_backing")
        data["backing"]["mounts"][0]["Destination"] = None
        self.assertEqual(run_check(data)["reason"], "contradictory_backing")
        data["backing"]["mounts"] = None
        self.assertEqual(run_check(data)["status"], "pass")

    def test_partial_export_can_have_additional_backing_observations(self):
        data = example("gap")
        extra = {**data["backing"]["mounts"][0], "Destination":"/job/another"}
        data["backing"]["mounts"].append(extra)
        self.assertEqual(run_check(data)["gaps"], [{"row":1,"basis":"same_object"}])

    def test_duplicate_native_destinations(self):
        data = example("gap")
        data["inspect"]["Mounts"] *= 2
        self.assertEqual(run_check(data)["unresolved"], [{"row":1,"reason":"duplicate_destination"},
                                                          {"row":2,"reason":"duplicate_destination"}])

    def test_empty_partial_and_contradictory_totals(self):
        data = example()
        data["inspect"]["Mounts"] = []
        data["inspect"]["total"] = 0
        del data["backing"]
        self.assertEqual(run_check(data)["status"], "pass")
        data["inspect"]["total"] = 1
        self.assertEqual(run_check(data)["reason"], "incomplete_mounts")
        for total in (-1, True, "0"):
            data["inspect"]["total"] = total
            self.assertEqual(run_check(data)["reason"], "contradictory_count")
        del data["inspect"]["Mounts"]
        self.assertEqual(run_check(data)["reason"], "mounts_unavailable")

    def test_confirmed_gap_and_a_second_unresolved_row(self):
        data = example("gap")
        data["inspect"]["Mounts"].append({"Type":"volume","Source":"/fixture/v","Destination":"/job/other"})
        out = run_check(data)
        self.assertEqual((out["status"],out["gaps"],out["unresolved"]),
                         ("gap",[{"row":1,"basis":"same_object"}],[{"row":2,"reason":"backing_unverified"}]))

    def test_raw_destination_or_source_redactions(self):
        for value in (None,"relative","//fixture","/fixture/../control","/fixture/<redacted>","/fixture/"):
            data = example("gap")
            data["inspect"]["Mounts"][0]["Destination"] = value
            self.assertEqual(run_check(data)["status"],"unknown")
        data = example("gap")
        data["backing"]["mounts"][0]["Source"] = data["inspect"]["Mounts"][0]["Source"] = "/fixture/REDACTED"
        self.assertEqual(run_check(data)["status"],"unknown")

    def test_invalid_shape_duplicate_keys_and_limits(self):
        for raw in (b"[]",b"{",b'{"job":{},"job":{}}',b'{"x":NaN}',b" "*(1024**2+1)):
            self.assertEqual(run_check(raw,2),{"status":"invalid_input"})
        data = example()
        data["inspect"]["Mounts"] = [deepcopy(data["inspect"]["Mounts"][0]) for _ in range(1025)]
        self.assertEqual(run_check(data,2),{"status":"invalid_input"})


if __name__ == "__main__":
    unittest.main()
