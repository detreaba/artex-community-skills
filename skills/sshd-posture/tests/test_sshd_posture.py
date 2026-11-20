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

    def __init__(self, banner, packet=b"", send_packet=True, proactive=False):
        self.banner = banner
        self.packet = packet
        self.send_packet = send_packet
        self.proactive = proactive
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
            if self.proactive:
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

    def test_ignore_flood_beyond_byte_cap_is_unknown(self):
        # The byte budget bounds a DoS flood: large IGNORE packets exceeding the
        # cap with no KEXINIT yield a bounded unknown, not a hang.
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


if __name__ == "__main__":
    unittest.main()
