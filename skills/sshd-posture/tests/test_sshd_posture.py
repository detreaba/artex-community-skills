"""Offline and loopback regressions for the sshd-posture check.

The verdict logic in check.py is tested on the examples and the rules; the
observe.py parser is tested against an in-process loopback fixture that emits a
real SSH identification string and a crafted KEXINIT packet. No test touches a
non-loopback address. Python 3.9 grammar, standard library only.
"""
import importlib.util
import json
from pathlib import Path
import socket
import struct
import subprocess
import sys
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
EXAMPLES = ROOT / "examples"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


check = _load("sshd_check", SCRIPTS / "check.py")
observe = _load("sshd_observe", SCRIPTS / "observe.py")

POLICY = {
    "forbidden": {
        "kex": ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1"],
        "hostkey": ["ssh-dss", "ssh-rsa"],
        "cipher": ["3des-cbc", "aes128-cbc", "arcfour"],
        "mac": ["hmac-md5", "hmac-sha1-96"],
    },
    "required": {
        "kex": ["curve25519-sha256"],
        "cipher": ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"],
        "mac": ["hmac-sha2-256-etm@openssh.com"],
    },
}


def _namelist(text):
    return struct.pack(">I", len(text)) + text.encode("ascii")


def _packet(payload):
    """Wrap a payload in a binary transport packet with valid padding."""
    base = 4 + 1 + len(payload)
    pad = 8 - (base % 8)
    if pad < 4:
        pad += 8
    return struct.pack(">I", 1 + len(payload) + pad) + bytes([pad]) + payload + b"\x00" * pad


def build_kexinit(kex, hostkey, enc, mac, comp=("none",)):
    """Build a well-formed SSH_MSG_KEXINIT binary packet (RFC 4253)."""
    parts = [",".join(kex), ",".join(hostkey), ",".join(enc), ",".join(enc),
             ",".join(mac), ",".join(mac), ",".join(comp), ",".join(comp), "", ""]
    payload = bytes([20]) + b"\x00" * 16
    for text in parts:
        payload += _namelist(text)
    payload += b"\x00" + struct.pack(">I", 0)  # first_kex_packet_follows, reserved
    return _packet(payload)


def _ignore_packet():
    return _packet(b"\x02" + struct.pack(">I", 0))  # SSH_MSG_IGNORE, empty string


def _debug_packet():
    return _packet(b"\x04\x00" + struct.pack(">I", 0) + struct.pack(">I", 0))  # SSH_MSG_DEBUG


def _big_ignore(size=34000):
    return _packet(b"\x02" + struct.pack(">I", size) + b"\x00" * size)  # large SSH_MSG_IGNORE


class Fixture:
    """A one-shot loopback SSH-ish listener: sends a banner, then (optionally) a
    KEXINIT packet, then closes."""

    def __init__(self, banner, packet=b"", send_packet=True, proactive=False,
                 wait_ident=False, write_close=False, wait_kexinit=False):
        self.banner = banner
        self.packet = packet
        self.send_packet = send_packet
        self.proactive = proactive
        self.wait_ident = wait_ident
        self.write_close = write_close
        self.wait_kexinit = wait_kexinit
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(1)
        self.port = self.srv.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def _serve(self):
        try:
            conn, _ = self.srv.accept()
            conn.settimeout(5)
            if self.write_close:
                # Server sends banner + KEXINIT, then closes WITHOUT reading the
                # observer's writes (no drain), so the observer's pipelined
                # identification+KEXINIT send may fail. The already-sent bytes stay
                # readable on POSIX.
                conn.sendall(self.banner + (self.packet if self.send_packet else b""))
                conn.close()
            elif self.wait_kexinit:
                # Server withholds its identification until it has read BOTH the
                # client's SSH- line and a full KEXINIT, then sends banner + KEXINIT.
                # If no client KEXINIT arrives (observer did not pipeline it), it
                # sends NOTHING -- so the observer only sees a reply when it pipelines.
                try:
                    self._read_client_kexinit(conn)
                except OSError:
                    conn.close()
                    return
                conn.sendall(self.banner + (self.packet if self.send_packet else b""))
                self._drain(conn)
            elif self.wait_ident:
                # Server withholds its identification string until it has read the
                # client's SSH- identification line, then sends banner + KEXINIT.
                self._read_client_ident(conn)
                conn.sendall(self.banner + (self.packet if self.send_packet else b""))
                self._drain(conn)
            elif self.proactive:
                # Server writes its banner and KEXINIT before reading anything, so
                # the observer parses the KEXINIT from the bytes trailing the
                # banner. Drain the observer's writes so closing never races them.
                conn.sendall(self.banner + (self.packet if self.send_packet else b""))
                self._drain(conn)
            else:
                # Server withholds its KEXINIT until it has read the observer's.
                conn.sendall(self.banner)
                try:
                    self._read_client_kexinit(conn)
                except OSError:
                    pass
                if self.send_packet:
                    conn.sendall(self.packet)
            conn.close()
        except OSError:
            pass
        finally:
            try:
                self.srv.close()
            except OSError:
                pass

    @staticmethod
    def _drain(conn):
        try:
            while conn.recv(4096):
                pass
        except OSError:
            pass

    @staticmethod
    def _read_client_ident(conn):
        buf = b""
        while b"\n" not in buf:
            chunk = conn.recv(256)
            if not chunk:
                raise OSError("client closed before identification")
            buf += chunk

    @staticmethod
    def _read_client_kexinit(conn):
        buf = b""
        while b"\n" not in buf:
            chunk = conn.recv(256)
            if not chunk:
                raise OSError("client closed before identification")
            buf += chunk
        buf = buf.split(b"\n", 1)[1]
        while len(buf) < 4:
            chunk = conn.recv(256)
            if not chunk:
                raise OSError("client closed before KEXINIT length")
            buf += chunk
        plen = struct.unpack(">I", buf[:4])[0]
        while len(buf) < 4 + plen:
            chunk = conn.recv(4096)
            if not chunk:
                raise OSError("client closed before KEXINIT body")
            buf += chunk

    def __exit__(self, *exc):
        try:
            self.srv.close()
        except OSError:
            pass


def _req(port, policy=None):
    return {"authorization_ref": "test",
            "target": {"host": "127.0.0.1", "port": port, "address": "127.0.0.1"},
            "policy": policy if policy is not None else {}}


class ExampleVerdicts(unittest.TestCase):
    def _overall(self, name):
        with (EXAMPLES / name).open(encoding="utf-8") as handle:
            return check.evaluate(json.load(handle))["overall"]

    def test_pass(self):
        self.assertEqual(self._overall("pass.json"), "pass")

    def test_gap(self):
        self.assertEqual(self._overall("gap.json"), "gap")

    def test_unknown(self):
        self.assertEqual(self._overall("unknown.json"), "unknown")


class VerdictRules(unittest.TestCase):
    def _rec(self, **kw):
        rec = {"kexinit_read": True, "protocol": "2.0", "policy": POLICY,
               "kex_algorithms": ["curve25519-sha256"],
               "server_host_key_algorithms": ["ssh-ed25519"],
               "encryption_c2s": ["chacha20-poly1305@openssh.com"],
               "encryption_s2c": ["chacha20-poly1305@openssh.com"],
               "mac_c2s": ["hmac-sha2-256-etm@openssh.com"],
               "mac_s2c": ["hmac-sha2-256-etm@openssh.com"]}
        rec.update(kw)
        return rec

    def test_forbidden_cipher_is_gap(self):
        out = check.evaluate(self._rec(encryption_s2c=["chacha20-poly1305@openssh.com", "3des-cbc"]))
        self.assertEqual(out["per_category"]["cipher"], "gap")
        self.assertEqual(out["overall"], "gap")

    def test_forbidden_cipher_in_s2c_direction_only_is_gap(self):
        # F-SSH-11: required cipher only in enc_c2s, forbidden cipher only in
        # enc_s2c -- the cipher category unions both directions.
        out = check.evaluate(self._rec(encryption_c2s=["chacha20-poly1305@openssh.com"],
                                       encryption_s2c=["3des-cbc"]))
        self.assertEqual(out["per_category"]["cipher"], "gap")
        self.assertEqual(out["overall"], "gap")

    def test_forbidden_mac_in_s2c_direction_only_is_gap(self):
        # forbidden MAC only in mac_s2c -- forbidden is the union of directions.
        out = check.evaluate(self._rec(mac_c2s=["hmac-sha2-256-etm@openssh.com"],
                                       mac_s2c=["hmac-md5"]))
        self.assertEqual(out["per_category"]["mac"], "gap")
        self.assertEqual(out["overall"], "gap")

    def test_required_cipher_missing_in_one_direction_is_gap(self):
        # F-SSH-12: required cipher offered only in enc_c2s; enc_s2c offers a
        # non-required, non-forbidden cipher. required is PER DIRECTION, so the
        # category is a gap even though the union contains a required name.
        out = check.evaluate(self._rec(encryption_c2s=["chacha20-poly1305@openssh.com"],
                                       encryption_s2c=["aes128-ctr"]))
        self.assertEqual(out["per_category"]["cipher"], "gap")
        self.assertEqual(out["overall"], "gap")

    def test_required_satisfied_per_direction_passes(self):
        # Sanity: each direction offers a required algorithm (different ones) -> pass.
        out = check.evaluate(self._rec(encryption_c2s=["chacha20-poly1305@openssh.com"],
                                       encryption_s2c=["aes256-gcm@openssh.com"]))
        self.assertEqual(out["per_category"]["cipher"], "pass")

    def test_required_mac_missing_in_one_direction_is_gap(self):
        # F-SSH-13: required MAC only in mac_c2s; mac_s2c offers a non-required,
        # non-forbidden MAC. The per-direction required rule applies to MAC too.
        out = check.evaluate(self._rec(mac_c2s=["hmac-sha2-256-etm@openssh.com"],
                                       mac_s2c=["umac-128@openssh.com"]))
        self.assertEqual(out["per_category"]["mac"], "gap")
        self.assertEqual(out["overall"], "gap")

    # --- Sweep: {forbidden, required} x {missing, empty, non-list} direction.
    # A category with one direction captured must still decide gap from that
    # direction; only an otherwise-clean but incomplete read is unknown.

    def test_forbidden_in_captured_direction_with_other_missing_is_gap(self):
        # A forbidden cipher visible in the captured direction is a gap even when
        # the opposite direction's list is absent from the record (guards the
        # regression where a missing direction masked the detection as unknown).
        rec = self._rec(encryption_c2s=["3des-cbc"])
        rec.pop("encryption_s2c")
        out = check.evaluate(rec)
        self.assertEqual(out["per_category"]["cipher"], "gap")
        self.assertEqual(out["overall"], "gap")

    def test_required_absent_in_captured_direction_with_other_missing_is_gap(self):
        # The captured direction offers none of the required set -> definite gap,
        # even with the opposite direction missing.
        rec = self._rec(encryption_c2s=["aes128-ctr"])
        rec.pop("encryption_s2c")
        out = check.evaluate(rec)
        self.assertEqual(out["per_category"]["cipher"], "gap")

    def test_required_met_in_captured_direction_but_other_missing_is_unknown(self):
        # Captured direction meets required and nothing is forbidden, but a
        # direction is missing -> cannot confirm a pass -> unknown (fails closed).
        rec = self._rec(encryption_c2s=["chacha20-poly1305@openssh.com"])
        rec.pop("encryption_s2c")
        out = check.evaluate(rec)
        self.assertEqual(out["per_category"]["cipher"], "unknown")

    def test_non_list_direction_still_detects_forbidden_in_other(self):
        # A non-list direction field is treated as not captured, but a forbidden
        # algorithm in the captured direction still decides gap.
        out = check.evaluate(self._rec(encryption_c2s=["arcfour"],
                                       encryption_s2c="not-a-list"))
        self.assertEqual(out["per_category"]["cipher"], "gap")

    def test_empty_direction_list_missing_required_is_gap(self):
        # An empty but present direction offers none of the required set -> gap.
        out = check.evaluate(self._rec(encryption_c2s=["chacha20-poly1305@openssh.com"],
                                       encryption_s2c=[]))
        self.assertEqual(out["per_category"]["cipher"], "gap")

    def test_both_directions_missing_is_unknown(self):
        # Neither direction captured -> the category reads unknown.
        rec = self._rec()
        rec.pop("encryption_c2s")
        rec.pop("encryption_s2c")
        out = check.evaluate(rec)
        self.assertEqual(out["per_category"]["cipher"], "unknown")

    def test_empty_mac_direction_is_gap_but_omitted_is_unknown(self):
        # F-SSH-14: a captured empty mac_s2c ([]) offers none of the required set
        # -> gap; the SAME record with mac_s2c OMITTED was not captured -> unknown.
        # Empty (captured, length 0 on the wire) and omitted (not captured) are
        # distinct inputs with distinct verdicts.
        empty = check.evaluate(self._rec(mac_c2s=["hmac-sha2-256-etm@openssh.com"],
                                         mac_s2c=[]))
        self.assertEqual(empty["per_category"]["mac"], "gap")
        self.assertEqual(empty["overall"], "gap")
        rec = self._rec(mac_c2s=["hmac-sha2-256-etm@openssh.com"])
        rec.pop("mac_s2c")
        omitted = check.evaluate(rec)
        self.assertEqual(omitted["per_category"]["mac"], "unknown")
        self.assertEqual(omitted["overall"], "unknown")

    def test_empty_direction_under_forbidden_only_passes(self):
        # An empty captured direction offers nothing forbidden -> pass under a
        # forbidden-only policy (the dual of empty-under-required -> gap). Pinned so
        # empty-offer semantics stay consistent across policy kinds: an empty list
        # is a real empty set, not an unreliable read.
        rec = {"kexinit_read": True, "protocol": "2.0",
               "policy": {"forbidden": {"hostkey": ["ssh-dss", "ssh-rsa"]}},
               "server_host_key_algorithms": [],
               "kex_algorithms": ["curve25519-sha256"],
               "encryption_c2s": ["chacha20-poly1305@openssh.com"],
               "encryption_s2c": ["chacha20-poly1305@openssh.com"],
               "mac_c2s": ["hmac-sha2-256-etm@openssh.com"],
               "mac_s2c": ["hmac-sha2-256-etm@openssh.com"]}
        out = check.evaluate(rec)
        self.assertEqual(out["per_category"]["hostkey"], "pass")

    def test_non_string_namelist_element_is_unknown(self):
        # A captured name-list carrying a non-string element is malformed -> the
        # category reads unknown rather than silently coercing to a clean pass.
        out = check.evaluate(self._rec(encryption_s2c=[["3des-cbc"]]))
        self.assertEqual(out["per_category"]["cipher"], "unknown")

    def test_non_string_namelist_element_still_gaps_on_real_forbidden(self):
        # A real forbidden name among valid strings still gaps even when the
        # opposite direction's list is malformed (forbidden is a positive detection).
        out = check.evaluate(self._rec(encryption_c2s=["3des-cbc"],
                                       encryption_s2c=[["x"]]))
        self.assertEqual(out["per_category"]["cipher"], "gap")

    def test_non_string_policy_element_is_unknown(self):
        # A forbidden policy list with a non-string element is unusable -> unknown,
        # never a false pass even when the offer contains the intended name.
        rec = self._rec(encryption_c2s=["3des-cbc"], encryption_s2c=["3des-cbc"])
        rec["policy"] = {"forbidden": {"cipher": [["3des-cbc"]]}}
        out = check.evaluate(rec)
        self.assertEqual(out["per_category"]["cipher"], "unknown")

    def test_required_matches_exact_token_not_substring(self):
        # F-SSH-15: required "hmac-sha2-256" against an offer of only
        # "hmac-sha2-256-etm@openssh.com" -> gap. Membership is exact token
        # equality, not prefix/suffix/substring. Offering the exact name -> pass.
        pol = {"required": {"mac": ["hmac-sha2-256"]}}
        etm = self._rec(mac_c2s=["hmac-sha2-256-etm@openssh.com"],
                        mac_s2c=["hmac-sha2-256-etm@openssh.com"])
        etm["policy"] = pol
        gap = check.evaluate(etm)
        self.assertEqual(gap["per_category"]["mac"], "gap")
        self.assertEqual(gap["overall"], "gap")
        exact = self._rec(mac_c2s=["hmac-sha2-256"], mac_s2c=["hmac-sha2-256"])
        exact["policy"] = pol
        self.assertEqual(check.evaluate(exact)["per_category"]["mac"], "pass")

    def test_algorithm_names_are_case_sensitive(self):
        # RFC 4251 algorithm names are case-sensitive: an upper-cased offer does
        # not satisfy a lower-case required name.
        rec = self._rec(mac_c2s=["HMAC-SHA2-256"], mac_s2c=["HMAC-SHA2-256"])
        rec["policy"] = {"required": {"mac": ["hmac-sha2-256"]}}
        self.assertEqual(check.evaluate(rec)["per_category"]["mac"], "gap")

    def test_forbidden_matches_exact_token_not_substring(self):
        # The forbidden dual of F-SSH-15: forbidding "hmac-sha2-256" does not
        # match an offer of only "hmac-sha2-256-etm@openssh.com" -> pass.
        rec = self._rec(mac_c2s=["hmac-sha2-256-etm@openssh.com"],
                        mac_s2c=["hmac-sha2-256-etm@openssh.com"])
        rec["policy"] = {"forbidden": {"mac": ["hmac-sha2-256"]}}
        self.assertEqual(check.evaluate(rec)["per_category"]["mac"], "pass")

    def test_clean_direction_lacking_required_gaps_despite_malformed_sibling(self):
        # A fully-parsed direction offering none of the required set is a gap even
        # when the opposite direction is malformed -- malformed must not mask a
        # definite required gap as unknown (guards the reorder of the malformed
        # check after the required check).
        out = check.evaluate(self._rec(encryption_c2s=["aes128-ctr"],
                                       encryption_s2c=[["x"]]))
        self.assertEqual(out["per_category"]["cipher"], "gap")
        self.assertEqual(out["overall"], "gap")

    def test_malformed_direction_does_not_assert_required_gap(self):
        # When the clean direction meets required and only the other direction is
        # malformed, the category is unknown (not gap): a malformed direction's
        # full offer is unknown, so it cannot by itself assert a required failure.
        out = check.evaluate(self._rec(encryption_c2s=["chacha20-poly1305@openssh.com"],
                                       encryption_s2c=[["x"]]))
        self.assertEqual(out["per_category"]["cipher"], "unknown")

    def test_unknown_policy_subkey_is_unknown(self):
        # A mistyped policy category ("ciphers" for "cipher") must not silently
        # drop the rule: the whole verdict fails closed to unknown, not a pass.
        rec = self._rec(encryption_c2s=["3des-cbc"], encryption_s2c=["3des-cbc"])
        rec["policy"] = {"forbidden": {"ciphers": ["3des-cbc"]}}
        self.assertEqual(check.evaluate(rec)["overall"], "unknown")

    def test_unknown_policy_top_key_is_unknown(self):
        # A mistyped top-level policy key ("forbiden" for "forbidden") is unusable
        # -> unknown, never a false pass.
        rec = self._rec(encryption_c2s=["3des-cbc"], encryption_s2c=["3des-cbc"])
        rec["policy"] = {"forbiden": {"cipher": ["3des-cbc"]}}
        self.assertEqual(check.evaluate(rec)["overall"], "unknown")

    def test_named_null_policy_category_is_unknown(self):
        # F-SSH-16: a NAMED policy category whose value is JSON null is malformed
        # (not a silent omit) -- the forbidden rule is not dropped; fail closed.
        rec = self._rec(encryption_c2s=["3des-cbc"], encryption_s2c=["3des-cbc"])
        rec["policy"] = {"forbidden": {"cipher": None},
                         "required": {"mac": ["hmac-sha2-256-etm@openssh.com"]}}
        out = check.evaluate(rec)
        self.assertEqual(out["per_category"]["cipher"], "unknown")
        self.assertEqual(out["overall"], "unknown")

    def test_null_forbidden_section_does_not_mask_required_gap(self):
        # A present-but-null forbidden section is unusable, but it must NOT mask a
        # definite required gap from the well-formed half: required cipher chacha20
        # vs an offer of only 3des-cbc -> gap (not unknown).
        rec = self._rec(encryption_c2s=["3des-cbc"], encryption_s2c=["3des-cbc"])
        rec["policy"] = {"forbidden": None,
                         "required": {"cipher": ["chacha20-poly1305@openssh.com"]}}
        self.assertEqual(check.evaluate(rec)["overall"], "gap")

    def test_unknown_policy_key_does_not_mask_a_gap(self):
        # A well-formed forbidden rule that gaps still gaps even when the policy
        # also carries an unknown category key alongside it.
        rec = self._rec(encryption_c2s=["3des-cbc"], encryption_s2c=["3des-cbc"])
        rec["policy"] = {"forbidden": {"cipher": ["3des-cbc"], "ciphers": []}}
        self.assertEqual(check.evaluate(rec)["overall"], "gap")

    def test_null_required_half_does_not_mask_forbidden_gap(self):
        # forbidden.cipher gaps on 3des-cbc; a null required.cipher (malformed half)
        # must not downgrade that definite gap to unknown.
        rec = self._rec(encryption_c2s=["3des-cbc"], encryption_s2c=["3des-cbc"])
        rec["policy"] = {"forbidden": {"cipher": ["3des-cbc"]},
                         "required": {"cipher": None}}
        self.assertEqual(check.evaluate(rec)["per_category"]["cipher"], "gap")

    def test_well_formed_forbidden_token_gaps_despite_non_string_sibling(self):
        # F-SSH-17: forbidden.cipher = ["3des-cbc", null] -- a well-formed forbidden
        # token next to a non-string sibling. The valid token still gaps on an
        # offered 3des-cbc; a malformed sibling must not discard the whole list.
        rec = self._rec(encryption_c2s=["3des-cbc"], encryption_s2c=["3des-cbc"])
        rec["policy"] = {"forbidden": {"cipher": ["3des-cbc", None]}}
        out = check.evaluate(rec)
        self.assertEqual(out["per_category"]["cipher"], "gap")
        self.assertEqual(out["overall"], "gap")

    def test_policy_list_with_only_non_string_is_unknown(self):
        # Contrast: a forbidden list with NO well-formed name ([null]) is unusable
        # -> unknown (nothing to match), never a false pass.
        rec = self._rec(encryption_c2s=["3des-cbc"], encryption_s2c=["3des-cbc"])
        rec["policy"] = {"forbidden": {"cipher": [None]}}
        self.assertEqual(check.evaluate(rec)["per_category"]["cipher"], "unknown")

    def test_partial_required_list_cannot_prove_a_miss(self):
        # Asymmetry: required.cipher = [chacha20, null] with an offer of only
        # aes256-gcm. The unreadable element may have been aes256-gcm, so a miss is
        # not provable -> unknown, NOT a false gap (unlike the forbidden side).
        rec = self._rec(encryption_c2s=["aes256-gcm@openssh.com"],
                        encryption_s2c=["aes256-gcm@openssh.com"])
        rec["policy"] = {"required": {"cipher": ["chacha20-poly1305@openssh.com", None]}}
        self.assertEqual(check.evaluate(rec)["per_category"]["cipher"], "unknown")

    def test_complete_required_list_proves_a_miss(self):
        # Control: the SAME miss against a COMPLETE required list IS a gap.
        rec = self._rec(encryption_c2s=["aes256-gcm@openssh.com"],
                        encryption_s2c=["aes256-gcm@openssh.com"])
        rec["policy"] = {"required": {"cipher": ["chacha20-poly1305@openssh.com"]}}
        self.assertEqual(check.evaluate(rec)["per_category"]["cipher"], "gap")

    def test_empty_policy_list_is_no_constraint(self):
        # An empty required (or forbidden) list, like an absent one, constrains
        # nothing -- the category is not judged.
        rec = self._rec()
        rec["policy"] = {"required": {"cipher": []}}
        self.assertNotIn("cipher", check.evaluate(rec)["per_category"])

    def test_whitespace_padded_token_is_malformed_unknown(self):
        # F-SSH-18: a captured token with a trailing space is not a well-formed
        # RFC 4251 name, so it cannot slip the forbidden match by reading as a
        # distinct algorithm; the list is malformed -> unknown, never a false pass.
        rec = self._rec(encryption_c2s=["3des-cbc "], encryption_s2c=["3des-cbc "])
        rec["policy"] = {"forbidden": {"cipher": ["3des-cbc"]}}
        self.assertEqual(check.evaluate(rec)["per_category"]["cipher"], "unknown")

    def test_well_formed_forbidden_gaps_despite_padded_sibling(self):
        # A real forbidden token alongside a padded (malformed) sibling still gaps.
        rec = self._rec(encryption_c2s=["3des-cbc", "aes128-cbc "],
                        encryption_s2c=["3des-cbc", "aes128-cbc "])
        rec["policy"] = {"forbidden": {"cipher": ["3des-cbc"]}}
        self.assertEqual(check.evaluate(rec)["per_category"]["cipher"], "gap")

    def test_whitespace_in_policy_token_is_malformed(self):
        # The dual: a whitespace policy token is not a well-formed name, so the
        # forbidden list is malformed; with no well-formed forbidden token it
        # cannot assert a gap, and reads unknown rather than a false pass.
        rec = self._rec(encryption_c2s=["3des-cbc"], encryption_s2c=["3des-cbc"])
        rec["policy"] = {"forbidden": {"cipher": ["3des-cbc "]}}
        self.assertEqual(check.evaluate(rec)["per_category"]["cipher"], "unknown")

    def test_malformed_at_sign_token_is_not_a_name(self):
        # RFC 4251 Sec. 6: the name@domain form has exactly one at-sign with a
        # non-empty part on each side. "3des-cbc@" (empty domain) and "3des-cbc@a@b"
        # (two at-signs) are not valid names -> they must not slip a forbidden set.
        for tok in ("3des-cbc@", "3des-cbc@a@b"):
            rec = self._rec(encryption_c2s=[tok], encryption_s2c=[tok])
            rec["policy"] = {"forbidden": {"cipher": ["3des-cbc"]}}
            self.assertEqual(check.evaluate(rec)["per_category"]["cipher"], "unknown",
                             "token %r should be malformed" % tok)

    def test_vendor_at_sign_name_is_valid(self):
        # A well-formed name@domain is a VALID (distinct) algorithm: offering
        # aes256-gcm@openssh.com satisfies a required set naming it, not malformed.
        rec = self._rec(encryption_c2s=["aes256-gcm@openssh.com"],
                        encryption_s2c=["aes256-gcm@openssh.com"])
        rec["policy"] = {"required": {"cipher": ["aes256-gcm@openssh.com"]}}
        self.assertEqual(check.evaluate(rec)["per_category"]["cipher"], "pass")

    def test_invalid_fqdn_at_sign_token_is_not_a_name(self):
        # RFC 4251 Sec. 6: the domain after @ must be a fully-qualified domain name.
        # "3des-cbc@x" (single label, no dot) and "3des-cbc@." (empty labels) are
        # not valid names -> malformed -> unknown, not a distinct-algorithm pass.
        for tok in ("3des-cbc@x", "3des-cbc@."):
            rec = self._rec(encryption_c2s=[tok], encryption_s2c=[tok])
            rec["policy"] = {"forbidden": {"cipher": ["3des-cbc"]}}
            self.assertEqual(check.evaluate(rec)["per_category"]["cipher"], "unknown",
                             "token %r should be malformed" % tok)

    def test_provable_required_miss_with_nonstandard_sibling_is_gap(self):
        # A direction whose elements are all STRINGS -- a valid non-required name
        # plus an empty or padded token -- definitively offers no required name, so
        # the miss is provable -> gap (a non-well-formed string can never be a
        # required name). Only a non-string sibling would make it unprovable.
        for sib in ("", "x "):
            out = check.evaluate(self._rec(encryption_c2s=["aes128-ctr", sib],
                                           encryption_s2c=["aes128-ctr", sib]))
            self.assertEqual(out["per_category"]["cipher"], "gap",
                             "sibling %r: required miss is provable" % sib)

    def test_non_string_sibling_leaves_required_unprovable_unknown(self):
        # Contrast: a NON-STRING sibling makes the direction unreadable, so a
        # required miss cannot be proved from it -> unknown (not gap).
        out = check.evaluate(self._rec(encryption_c2s=["aes128-ctr", ["x"]],
                                       encryption_s2c=["aes128-ctr", ["x"]]))
        self.assertEqual(out["per_category"]["cipher"], "unknown")

    def test_at_sign_name_is_fully_case_sensitive(self):
        # RFC 4251 Sec. 6 makes the whole name case-sensitive, INCLUDING the domain
        # part (no DNS case-insensitivity carve-out in Sec. 6). So an offer that
        # differs from a forbidden name only in domain case is a DISTINCT algorithm
        # and is not matched -> pass. (Declined F-SSH-21: domain-case folding would
        # contradict the literal Sec. 6 text; left to the owner if desired.)
        rec = self._rec(encryption_c2s=["3des-cbc@OpenSSH.COM"],
                        encryption_s2c=["3des-cbc@OpenSSH.COM"])
        rec["policy"] = {"forbidden": {"cipher": ["3des-cbc@openssh.com"]}}
        self.assertEqual(check.evaluate(rec)["per_category"]["cipher"], "pass")

    def test_at_sign_required_domain_case_mismatch_is_gap(self):
        # The dual: an offer whose domain case differs from a required name does NOT
        # satisfy it (distinct names per Sec. 6) -> gap, not a false pass.
        rec = self._rec(mac_c2s=["hmac-sha2-256-etm@OpenSSH.COM"],
                        mac_s2c=["hmac-sha2-256-etm@OpenSSH.COM"])
        rec["policy"] = {"required": {"mac": ["hmac-sha2-256-etm@openssh.com"]}}
        self.assertEqual(check.evaluate(rec)["per_category"]["mac"], "gap")

    def test_local_part_case_is_significant(self):
        # The local part is likewise case-sensitive: "3DES-CBC@openssh.com" is a
        # distinct algorithm from forbidden "3des-cbc@openssh.com" -> not a gap.
        rec = self._rec(encryption_c2s=["3DES-CBC@openssh.com"],
                        encryption_s2c=["3DES-CBC@openssh.com"])
        rec["policy"] = {"forbidden": {"cipher": ["3des-cbc@openssh.com"]}}
        self.assertEqual(check.evaluate(rec)["per_category"]["cipher"], "pass")

    def test_numeric_label_domain_is_a_distinct_name_boundary(self):
        # Boundary decision (F-SSH-22): _is_name requires >=2 non-empty domain
        # labels but does not enforce full RFC 1034/3696 FQDN semantics (e.g. an
        # all-numeric label). "3des-cbc@127.0.0.1" is a valid distinct name, not the
        # forbidden "3des-cbc@openssh.com" -> pass. It cannot slip a standard
        # forbidden name; deeper FQDN validation is deferred to the owner.
        rec = self._rec(encryption_c2s=["3des-cbc@127.0.0.1"],
                        encryption_s2c=["3des-cbc@127.0.0.1"])
        rec["policy"] = {"forbidden": {"cipher": ["3des-cbc@openssh.com"]}}
        self.assertEqual(check.evaluate(rec)["per_category"]["cipher"], "pass")

    def test_absent_policy_category_is_no_constraint(self):
        # Control for F-SSH-16: a category simply ABSENT (not null) is no
        # constraint -- an unrelated offer is not judged against it.
        rec = self._rec(encryption_c2s=["3des-cbc"], encryption_s2c=["3des-cbc"],
                        mac_c2s=["hmac-sha2-256-etm@openssh.com"],
                        mac_s2c=["hmac-sha2-256-etm@openssh.com"])
        rec["policy"] = {"forbidden": {"mac": ["hmac-md5"]},
                         "required": {"mac": ["hmac-sha2-256-etm@openssh.com"]}}
        out = check.evaluate(rec)
        self.assertNotIn("cipher", out["per_category"])
        self.assertEqual(out["overall"], "pass")

    def test_no_kexinit_read_is_unknown_even_with_namelists(self):
        # Pre-empts the kexinit_read contradiction: if the observer did not read a
        # KEXINIT, stray name-lists are not trusted -> unknown (the flag gates).
        rec = self._rec(encryption_c2s=["3des-cbc"], encryption_s2c=["3des-cbc"])
        rec["kexinit_read"] = False
        out = check.evaluate(rec)
        self.assertEqual(out["per_category"]["cipher"], "unknown")
        self.assertEqual(out["overall"], "unknown")

    def test_falsy_error_does_not_mask_a_gap_but_downgrades_clean(self):
        # F-SSH-25: a present-but-falsy "error" (null/false/"") must not mask a
        # captured forbidden algorithm -> the gap wins. But it is a non-standard
        # record signal (observe.py omits the key on success), so an otherwise-clean
        # verdict downgrades to unknown (fail-closed), consistent with the
        # present-but-unusable policy rule.
        for falsy in (None, False, ""):
            gap_rec = self._rec(encryption_c2s=["3des-cbc"],
                                encryption_s2c=["chacha20-poly1305@openssh.com"])
            gap_rec["error"] = falsy
            self.assertEqual(check.evaluate(gap_rec)["overall"], "gap",
                             "error=%r must not mask the forbidden cipher" % (falsy,))
            clean_rec = self._rec()  # every category clean under POLICY
            clean_rec["error"] = falsy
            self.assertEqual(check.evaluate(clean_rec)["overall"], "unknown",
                             "error=%r downgrades a clean verdict to unknown" % (falsy,))

    def test_truthy_error_does_not_mask_a_gap_but_downgrades_clean(self):
        # F-SSH-27: a truthy "error" ("timeout"/"invalid_input") is a record anomaly,
        # not a mask -- a captured forbidden algorithm still gaps (the kexinit_read
        # gate means name-lists are judged only when fully parsed, so the gap is
        # real), while an otherwise-clean verdict downgrades to unknown. (Revises the
        # F-SSH-25 statement that a truthy error always reads unknown.)
        for err in ("timeout", "invalid_input"):
            gap_rec = self._rec(encryption_c2s=["3des-cbc"],
                                encryption_s2c=["chacha20-poly1305@openssh.com"])
            gap_rec["error"] = err
            self.assertEqual(check.evaluate(gap_rec)["overall"], "gap",
                             "error=%r must not mask the forbidden cipher" % err)
            clean_rec = self._rec()
            clean_rec["error"] = err
            self.assertEqual(check.evaluate(clean_rec)["overall"], "unknown",
                             "error=%r downgrades a clean verdict to unknown" % err)

    def test_fail_record_shape_is_unknown_and_surfaces_reason(self):
        # A real observe.py _fail record: error + reason, NO policy, NO name-lists ->
        # nothing to judge -> unknown; the reason is surfaced as a note.
        rec = {"skill": "sshd-posture", "observation_version": 1,
               "error": "invalid_input",
               "reason": "target.host must be one host, not a list, range or wildcard"}
        out = check.evaluate(rec)
        self.assertEqual(out["overall"], "unknown")
        self.assertTrue(any("invalid_input" in n for n in out.get("notes", [])),
                        "the error/reason should be surfaced in notes")

    def test_only_boolean_true_kexinit_read_is_trusted(self):
        # F-SSH-28 / F-SSH-16: the gate requires JSON boolean True -- the one value
        # observe.py writes once a KEXINIT is fully parsed. A non-boolean 1 / "true",
        # or the truthy-but-negative "false", reads unknown even with a captured
        # forbidden cipher; only boolean True lets it gap. The flag is the single
        # statement that the name-lists are complete, so it cannot be coerced.
        for flag in (1, "true", "false"):
            rec = self._rec(encryption_c2s=["3des-cbc"],
                            encryption_s2c=["chacha20-poly1305@openssh.com"])
            rec["kexinit_read"] = flag
            self.assertEqual(check.evaluate(rec)["overall"], "unknown",
                             "kexinit_read=%r must gate to unknown" % (flag,))
        gap_rec = self._rec(encryption_c2s=["3des-cbc"],
                            encryption_s2c=["chacha20-poly1305@openssh.com"])
        gap_rec["kexinit_read"] = True
        self.assertEqual(check.evaluate(gap_rec)["overall"], "gap")

    def test_required_kex_absent_is_gap(self):
        out = check.evaluate(self._rec(kex_algorithms=["ecdh-sha2-nistp256"]))
        self.assertEqual(out["per_category"]["kex"], "gap")

    def test_protocol_v1_is_advisory_not_gap(self):
        # F-SSH-1: the banner's protocol token is self-reported, so it is advisory
        # (a note), not a verdict. A clean algorithm offer with an SSH-1.99 banner
        # still passes, and no "protocol" category is emitted.
        out = check.evaluate(self._rec(protocol="1.99"))
        self.assertEqual(out["overall"], "pass")
        self.assertNotIn("protocol", out["per_category"])
        self.assertTrue(any("1.99" in n for n in out["notes"]))

    def test_no_kexinit_is_unknown(self):
        out = check.evaluate(self._rec(kexinit_read=False))
        self.assertEqual(out["per_category"]["kex"], "unknown")
        self.assertEqual(out["overall"], "unknown")

    def test_clean_server_passes(self):
        self.assertEqual(check.evaluate(self._rec())["overall"], "pass")

    def test_error_record_is_unknown(self):
        self.assertEqual(check.evaluate({"error": "invalid_input", "reason": "x"})["overall"], "unknown")

    def test_malformed_fail_closed(self):
        for payload in (b'{"policy":{"forbidden":{"kex":1}},"kexinit_read":true,"protocol":"2.0"}',
                        b'{"kex_algorithms":"not-a-list","kexinit_read":true,"protocol":"2.0","policy":{"required":{"kex":["x"]}}}',
                        b'not json'):
            proc = subprocess.run([sys.executable, "-B", str(SCRIPTS / "check.py")],
                                  input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(proc.returncode, 0, proc.stderr.decode("utf-8", "replace"))
            self.assertEqual(json.loads(proc.stdout.decode("utf-8"))["overall"], "unknown")


class ObserveGuards(unittest.TestCase):
    def test_requires_authorization_ref(self):
        _, err = observe._validate({"target": {"host": "127.0.0.1", "port": 22}})
        self.assertIn("authorization_ref", err)

    def test_rejects_host_list_and_wildcard(self):
        for host in ("a.example,b.example", "*.example.com", "10.0.0.0/24"):
            _, err = observe._validate({"authorization_ref": "x", "target": {"host": host, "port": 22}})
            self.assertIsNotNone(err)

    def test_rejects_hostname_address(self):
        _, err = observe._validate({"authorization_ref": "x",
                                    "target": {"host": "127.0.0.1", "port": 22, "address": "evil.example"}})
        self.assertIn("IP literal", err)

    def test_rejects_bad_port_and_policy(self):
        _, err = observe._validate({"authorization_ref": "x", "target": {"host": "127.0.0.1", "port": 0}})
        self.assertIn("port", err)
        _, err = observe._validate({"authorization_ref": "x", "target": {"host": "127.0.0.1"}, "policy": "nope"})
        self.assertIn("policy", err)

    def test_default_port_22(self):
        valid, err = observe._validate({"authorization_ref": "x", "target": {"host": "127.0.0.1"}})
        self.assertIsNone(err)


class LoopbackParser(unittest.TestCase):
    def test_parses_modern_offer_and_passes(self):
        packet = build_kexinit(
            kex=["curve25519-sha256", "ecdh-sha2-nistp256"],
            hostkey=["ssh-ed25519", "rsa-sha2-512"],
            enc=["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes256-ctr"],
            mac=["hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com"])
        with Fixture(b"SSH-2.0-FixtureSSH_1.0\r\n", packet, proactive=True) as fx:
            rec = observe.observe(_req(fx.port, POLICY))
        self.assertTrue(rec["kexinit_read"])
        self.assertEqual(rec["protocol"], "2.0")
        self.assertEqual(rec["software"], "FixtureSSH_1.0")
        self.assertIn("curve25519-sha256", rec["kex_algorithms"])
        self.assertEqual(rec["connections_made"], 1)
        self.assertEqual(check.evaluate(rec)["overall"], "pass")

    def test_parses_weak_offer_and_gaps(self):
        packet = build_kexinit(
            kex=["curve25519-sha256", "diffie-hellman-group1-sha1"],
            hostkey=["ssh-rsa"],
            enc=["aes128-ctr", "3des-cbc"],
            mac=["hmac-sha2-256", "hmac-md5"])
        with Fixture(b"SSH-2.0-OldServer_6.6\r\n", packet) as fx:
            rec = observe.observe(_req(fx.port, POLICY))
        self.assertTrue(rec["kexinit_read"])
        out = check.evaluate(rec)
        self.assertEqual(out["overall"], "gap")
        self.assertEqual(out["per_category"]["kex"], "gap")
        self.assertEqual(out["per_category"]["cipher"], "gap")

    def test_padded_token_on_the_wire_fails_closed(self):
        # observe.py records tokens verbatim (a trailing space is kept); check.py is
        # the hygiene gate. Under a forbidden-only policy a padded token cannot be
        # confirmed clean -> unknown (it may disguise the forbidden algorithm).
        packet = build_kexinit(
            kex=["curve25519-sha256"], hostkey=["ssh-ed25519"],
            enc=["3des-cbc "],  # trailing space on the wire
            mac=["hmac-sha2-256-etm@openssh.com"])
        with Fixture(b"SSH-2.0-PaddedSSH_1.0\r\n", packet) as fx:
            rec = observe.observe(_req(fx.port, {"forbidden": {"cipher": ["3des-cbc"]}}))
        self.assertEqual(rec["encryption_c2s"], ["3des-cbc "])  # recorded verbatim
        self.assertEqual(check.evaluate(rec)["per_category"]["cipher"], "unknown")

    def test_comma_only_namelist_is_recorded_faithfully_and_flagged(self):
        # F-SSH-19: observe.py records tokens faithfully (no empty-drop), so a
        # comma-only body "," reaches check.py as empty tokens -- not a length-0
        # empty offer -- and reads unknown rather than taking the empty-offer pass.
        packet = build_kexinit(
            kex=["curve25519-sha256"], hostkey=["ssh-ed25519"],
            enc=["", ""],  # ",".join -> body "," on the wire -> two empty tokens
            mac=["hmac-sha2-256-etm@openssh.com"])
        with Fixture(b"SSH-2.0-CommaSSH_1.0\r\n", packet) as fx:
            rec = observe.observe(_req(fx.port, {"forbidden": {"cipher": ["3des-cbc"]}}))
        self.assertEqual(rec["encryption_c2s"], ["", ""])  # faithful, not dropped
        self.assertEqual(check.evaluate(rec)["per_category"]["cipher"], "unknown")

    def test_length_zero_namelist_is_a_genuine_empty_offer(self):
        # Contrast to the comma-only case: a length-0 name-list ("" on the wire) is
        # a genuine empty offer -- it stays [] and takes the empty-offer path (pass
        # under a forbidden-only policy), distinct from ","(-> unknown).
        packet = build_kexinit(
            kex=["curve25519-sha256"], hostkey=["ssh-ed25519"],
            enc=[""],  # ",".join([""]) == "" -> length-0 name-list
            mac=["hmac-sha2-256-etm@openssh.com"])
        with Fixture(b"SSH-2.0-EmptyOffer_1.0\r\n", packet) as fx:
            rec = observe.observe(_req(fx.port, {"forbidden": {"cipher": ["3des-cbc"]}}))
        self.assertEqual(rec["encryption_c2s"], [])  # genuine empty offer
        self.assertEqual(check.evaluate(rec)["per_category"]["cipher"], "pass")

    def test_waits_for_client_identification_before_banner(self):
        # F-SSH-23: a server that withholds its identification string until it has
        # read the client's SSH- line. observe.py sends its identification first
        # (RFC 4253 Sec. 4.2 allows either peer first), so the server's KEXINIT --
        # with a forbidden kex -- is still captured -> gap, not a timeout -> unknown.
        packet = build_kexinit(
            kex=["curve25519-sha256", "diffie-hellman-group1-sha1"],
            hostkey=["ssh-ed25519"],
            enc=["chacha20-poly1305@openssh.com"],
            mac=["hmac-sha2-256-etm@openssh.com"])
        with Fixture(b"SSH-2.0-WaitIdent_1.0\r\n", packet, wait_ident=True) as fx:
            rec = observe.observe(_req(fx.port, POLICY))
        self.assertTrue(rec["kexinit_read"])
        self.assertIn("diffie-hellman-group1-sha1", rec["kex_algorithms"])
        out = check.evaluate(rec)
        self.assertEqual(out["per_category"]["kex"], "gap")
        self.assertEqual(out["overall"], "gap")

    def test_extra_blank_line_after_identification_is_unknown(self):
        # F-SSH-26: RFC 4253 Sec. 4.2 -- the identification is terminated by a SINGLE
        # CR LF, and "All packets following the identification string SHALL use the
        # binary packet protocol". An extra CR LF (or LF) after the SSH- line is not
        # a binary packet; it frames as an out-of-bounds packet_length, so the
        # observation reads unknown (fail-closed, not a false clean). Declined:
        # resynchronising past stray post-terminator bytes is a separate owner call.
        packet = build_kexinit(
            kex=["curve25519-sha256", "diffie-hellman-group1-sha1"],
            hostkey=["ssh-ed25519"], enc=["chacha20-poly1305@openssh.com"],
            mac=["hmac-sha2-256-etm@openssh.com"])
        for banner in (b"SSH-2.0-ExtraCRLF_1.0\r\n\r\n", b"SSH-2.0-ExtraLF_1.0\r\n\n"):
            with Fixture(banner, packet, proactive=True) as fx:
                rec = observe.observe(_req(fx.port, POLICY))
            self.assertFalse(rec["kexinit_read"], "banner %r should not parse" % banner)
            self.assertEqual(check.evaluate(rec)["overall"], "unknown")
        # Contrast: a single CR LF terminator captures the forbidden kex -> gap.
        with Fixture(b"SSH-2.0-OK_1.0\r\n", packet, proactive=True) as fx:
            rec = observe.observe(_req(fx.port, POLICY))
        self.assertTrue(rec["kexinit_read"])
        self.assertEqual(check.evaluate(rec)["per_category"]["kex"], "gap")

    def test_waits_for_client_kexinit_before_banner(self):
        # F-SSH-24: a server that withholds its identification until it has read the
        # client's SSH- line AND a full KEXINIT. observe.py pipelines its ident and
        # KEXINIT (RFC 4253 Sec. 5.2), so the server's KEXINIT -- with a forbidden
        # kex -- is still captured -> gap, not a deadlock -> unknown.
        packet = build_kexinit(
            kex=["curve25519-sha256", "diffie-hellman-group1-sha1"],
            hostkey=["ssh-ed25519"], enc=["chacha20-poly1305@openssh.com"],
            mac=["hmac-sha2-256-etm@openssh.com"])
        with Fixture(b"SSH-2.0-WaitKexinit_1.0\r\n", packet, wait_kexinit=True) as fx:
            rec = observe.observe(_req(fx.port, POLICY))
        self.assertTrue(rec["kexinit_read"])
        self.assertIn("diffie-hellman-group1-sha1", rec["kex_algorithms"])
        out = check.evaluate(rec)
        self.assertEqual(out["per_category"]["kex"], "gap")
        self.assertEqual(out["overall"], "gap")

    @unittest.skipIf(sys.platform.startswith("win"),
                     "Windows recv discards buffered data on RST; validated on Linux CI")
    def test_peer_closes_before_observer_finishes_sending(self):
        # The observer's best-effort pipelined send fails against a peer that
        # already sent its banner + KEXINIT (forbidden kex) and closed; the send
        # failure must be noted, not fatal, so the KEXINIT already received is parsed
        # -> gap, never discarded to unknown. (POSIX keeps the buffered bytes
        # readable after the peer's close; Windows recv may not, hence skipped.)
        packet = build_kexinit(
            kex=["curve25519-sha256", "diffie-hellman-group1-sha1"],
            hostkey=["ssh-ed25519"], enc=["chacha20-poly1305@openssh.com"],
            mac=["hmac-sha2-256-etm@openssh.com"])
        with Fixture(b"SSH-2.0-WriteClose_1.0\r\n", packet, write_close=True) as fx:
            rec = observe.observe(_req(fx.port, POLICY))
        self.assertTrue(rec["kexinit_read"])
        self.assertEqual(check.evaluate(rec)["overall"], "gap")

    def test_skips_ignore_and_debug_before_kexinit(self):
        # F-SSH-2: a server may send SSH_MSG_IGNORE / DEBUG before KEXINIT; the
        # observer must skip them and still read the real (here, weak) offer.
        packet = _ignore_packet() + _debug_packet() + build_kexinit(
            kex=["curve25519-sha256", "diffie-hellman-group1-sha1"],
            hostkey=["ssh-ed25519"], enc=["chacha20-poly1305@openssh.com"],
            mac=["hmac-sha2-256"])
        with Fixture(b"SSH-2.0-OpenSSH_9.6\r\n", packet) as fx:
            rec = observe.observe(_req(fx.port, POLICY))
        self.assertTrue(rec["kexinit_read"])
        self.assertIn("diffie-hellman-group1-sha1", rec["kex_algorithms"])
        out = check.evaluate(rec)
        self.assertEqual(out["per_category"]["kex"], "gap")
        self.assertEqual(out["overall"], "gap")

    def test_skips_many_ignore_packets_before_kexinit(self):
        # F-SSH-4: there is no count cap on SSH_MSG_IGNORE; a dozen of them before
        # KEXINIT must still be skipped and the real offer read.
        packet = (_ignore_packet() * 12) + build_kexinit(
            kex=["curve25519-sha256", "diffie-hellman-group1-sha1"],
            hostkey=["ssh-ed25519"], enc=["chacha20-poly1305@openssh.com"],
            mac=["hmac-sha2-256"])
        with Fixture(b"SSH-2.0-OpenSSH_9.6\r\n", packet) as fx:
            rec = observe.observe(_req(fx.port, POLICY))
        self.assertTrue(rec["kexinit_read"])
        self.assertIn("diffie-hellman-group1-sha1", rec["kex_algorithms"])
        self.assertEqual(check.evaluate(rec)["per_category"]["kex"], "gap")

    def test_large_ignore_flood_then_kexinit_is_gap(self):
        # F-SSH-6: ~9x32 KB IGNORE packets (over the old 256 KB byte cap) followed
        # by a KEXINIT are read within the time window, so the forbidden kex is
        # still observed.
        packet = (_big_ignore(32768) * 9) + build_kexinit(
            kex=["curve25519-sha256", "diffie-hellman-group1-sha1"],
            hostkey=["ssh-ed25519"], enc=["chacha20-poly1305@openssh.com"],
            mac=["hmac-sha2-256"])
        with Fixture(b"SSH-2.0-OpenSSH_9.6\r\n", packet) as fx:
            rec = observe.observe(_req(fx.port, POLICY))
        self.assertTrue(rec["kexinit_read"])
        self.assertEqual(check.evaluate(rec)["per_category"]["kex"], "gap")

    def test_flood_without_kexinit_is_unknown(self):
        # A flood of IGNORE packets with no KEXINIT (server then closes) -> unknown.
        with Fixture(b"SSH-2.0-OpenSSH_9.6\r\n", _big_ignore() * 9) as fx:
            rec = observe.observe(_req(fx.port, POLICY))
        self.assertFalse(rec["kexinit_read"])
        self.assertEqual(check.evaluate(rec)["overall"], "unknown")

    def test_empty_token_in_namelist_keeps_forbidden_name(self):
        # F-SSH-5: a kex name-list "curve25519-sha256,,diffie-hellman-group1-sha1"
        # (empty token) must not drop the forbidden name after it.
        packet = build_kexinit(kex=["curve25519-sha256", "", "diffie-hellman-group1-sha1"],
                               hostkey=["ssh-ed25519"], enc=["chacha20-poly1305@openssh.com"],
                               mac=["hmac-sha2-256"])
        with Fixture(b"SSH-2.0-OpenSSH_9.6\r\n", packet) as fx:
            rec = observe.observe(_req(fx.port, POLICY))
        self.assertTrue(rec["kexinit_read"])
        self.assertIn("diffie-hellman-group1-sha1", rec["kex_algorithms"])
        out = check.evaluate(rec)
        self.assertEqual(out["per_category"]["kex"], "gap")
        self.assertEqual(out["overall"], "gap")

    def test_sends_client_kexinit_when_server_waits(self):
        # F-SSH-3: a server that withholds its KEXINIT until it reads the client's
        # must still be observed -- the observer sends its own KEXINIT.
        packet = build_kexinit(kex=["curve25519-sha256", "diffie-hellman-group1-sha1"],
                               hostkey=["ssh-ed25519"], enc=["chacha20-poly1305@openssh.com"],
                               mac=["hmac-sha2-256"])
        with Fixture(b"SSH-2.0-OpenSSH_9.6\r\n", packet) as fx:  # default: waits for our KEXINIT
            rec = observe.observe(_req(fx.port, POLICY))
        self.assertTrue(rec["kexinit_read"])
        self.assertIn("diffie-hellman-group1-sha1", rec["kex_algorithms"])
        out = check.evaluate(rec)
        self.assertEqual(out["per_category"]["kex"], "gap")
        self.assertEqual(out["overall"], "gap")

    def test_banner_only_then_close_is_unknown(self):
        with Fixture(b"SSH-2.0-OpenSSH_9.6\r\n", b"", send_packet=False) as fx:
            rec = observe.observe(_req(fx.port, POLICY))
        self.assertFalse(rec["kexinit_read"])
        self.assertEqual(rec["protocol"], "2.0")
        self.assertEqual(check.evaluate(rec)["overall"], "unknown")

    def test_preamble_lines_before_ssh_line(self):
        banner = b"my legal banner line\r\nsecond line\r\nSSH-2.0-Guarded_1.0\r\n"
        packet = build_kexinit(kex=["curve25519-sha256"], hostkey=["ssh-ed25519"],
                               enc=["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"],
                               mac=["hmac-sha2-256-etm@openssh.com"])
        with Fixture(banner, packet) as fx:
            rec = observe.observe(_req(fx.port, POLICY))
        self.assertEqual(rec["software"], "Guarded_1.0")
        self.assertTrue(rec["kexinit_read"])

    def test_lf_only_identification_terminator(self):
        # F-SSH-8: RFC 4253 4.2 -- an identification string with no trailing CR
        # ("SSH-2.0-...\n") MUST be accepted; a 0x0d inside the following KEXINIT
        # must not confuse the line split.
        kexinit = build_kexinit(kex=["curve25519-sha256", "diffie-hellman-group1-sha1"],
                                hostkey=["ssh-ed25519"], enc=["chacha20-poly1305@openssh.com"],
                                mac=["hmac-sha2-256"])
        with Fixture(b"SSH-2.0-OpenSSH_9.6\n", kexinit, proactive=True) as fx:
            rec = observe.observe(_req(fx.port, POLICY))
        self.assertTrue(rec["kexinit_read"])
        self.assertEqual(rec["software"], "OpenSSH_9.6")
        self.assertEqual(check.evaluate(rec)["per_category"]["kex"], "gap")

    def test_pre_banner_line_containing_ssh_substring_is_not_identification(self):
        # F-SSH-9: a pre-banner line that merely CONTAINS "SSH-" after other text
        # ("Note: SSH-2.0-decoy") must be discarded; the identification is the next
        # line that BEGINS with "SSH-".
        banner = b"Note: SSH-2.0-decoy\r\nSSH-2.0-OpenSSH_9.6\r\n"
        kexinit = build_kexinit(kex=["curve25519-sha256", "diffie-hellman-group1-sha1"],
                                hostkey=["ssh-ed25519"], enc=["chacha20-poly1305@openssh.com"],
                                mac=["hmac-sha2-256"])
        with Fixture(banner, kexinit, proactive=True) as fx:
            rec = observe.observe(_req(fx.port, POLICY))
        self.assertTrue(rec["kexinit_read"])
        self.assertEqual(rec["software"], "OpenSSH_9.6")
        self.assertNotIn("decoy", rec.get("banner") or "")
        self.assertEqual(check.evaluate(rec)["per_category"]["kex"], "gap")

    def test_identification_comment_field_is_dropped_from_software(self):
        # RFC 4253 4.2: "SSH-protoversion-softwareversion SP comments". The comment
        # must not become part of software, and the KEXINIT leftover is taken after
        # the line terminator, not after the space.
        banner = b"SSH-2.0-OpenSSH_9.6 a friendly comment\r\n"
        kexinit = build_kexinit(kex=["curve25519-sha256", "diffie-hellman-group1-sha1"],
                                hostkey=["ssh-ed25519"], enc=["chacha20-poly1305@openssh.com"],
                                mac=["hmac-sha2-256"])
        with Fixture(banner, kexinit, proactive=True) as fx:
            rec = observe.observe(_req(fx.port, POLICY))
        self.assertTrue(rec["kexinit_read"])
        self.assertEqual(rec["software"], "OpenSSH_9.6")
        self.assertEqual(rec["protocol"], "2.0")
        self.assertEqual(check.evaluate(rec)["per_category"]["kex"], "gap")

    def test_long_pre_banner_line_under_per_line_cap(self):
        # A 300 B pre-banner line (over RFC 4253 4.2's SHOULD-NOT 255, well under
        # the 4096 B per-line memory cap) is discarded and the identification read.
        banner = (b"y" * 298 + b"\r\n") + b"SSH-2.0-OpenSSH_9.6\r\n"
        kexinit = build_kexinit(kex=["curve25519-sha256", "diffie-hellman-group1-sha1"],
                                hostkey=["ssh-ed25519"], enc=["chacha20-poly1305@openssh.com"],
                                mac=["hmac-sha2-256"])
        with Fixture(banner, kexinit, proactive=True) as fx:
            rec = observe.observe(_req(fx.port, POLICY))
        self.assertTrue(rec["kexinit_read"])
        self.assertEqual(rec["software"], "OpenSSH_9.6")
        self.assertEqual(check.evaluate(rec)["per_category"]["kex"], "gap")

    def test_many_pre_banner_lines_then_identification(self):
        # F-SSH-7: 80 valid CRLF pre-banner lines (~9.9 KB, over the old 64-line /
        # 8 KiB cap), then the SSH- identification and a KEXINIT on the same send ->
        # read within the time window; the forbidden kex is still observed.
        pre = b"".join(b"pre-banner notice %03d " % i + b"x" * 100 + b"\r\n" for i in range(80))
        banner = pre + b"SSH-2.0-OpenSSH_9.6\r\n"
        kexinit = build_kexinit(kex=["curve25519-sha256", "diffie-hellman-group1-sha1"],
                                hostkey=["ssh-ed25519"], enc=["chacha20-poly1305@openssh.com"],
                                mac=["hmac-sha2-256"])
        with Fixture(banner, kexinit, proactive=True) as fx:
            rec = observe.observe(_req(fx.port, POLICY))
        self.assertTrue(rec["kexinit_read"])
        self.assertEqual(rec["software"], "OpenSSH_9.6")
        self.assertEqual(check.evaluate(rec)["per_category"]["kex"], "gap")


if __name__ == "__main__":
    unittest.main()
