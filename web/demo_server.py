"""
demo_server.py  -  browser based inspector for the E2EE chat.

WHY THIS EXISTS
Running the system properly needs three terminals. That is fine for me and
awkward for anyone marking it. This serves one page showing all three views
at once: Alice, the relay, and Bob.

IMPORTANT: this is a VIEWER, not a second implementation. Every key exchange,
every encryption and every tag check below calls the same crypto_core.py that
src/client.py uses. Nothing cryptographic is reimplemented here. If I broke
crypto_core, this page would break with it.

Standard library only, so there is nothing extra to install.

Run:  python3 web/demo_server.py     then open http://127.0.0.1:8000
"""

import json
import io
import os
import sys
import threading
import unittest
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from crypto_core import (generate_keypair, serialise_public, deserialise_public,
                         derive_session_keys, fingerprint, SecureSession,
                         ReplayError, RFC3526_GROUP14_P, RFC3526_GROUP14_G)
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HERE = os.path.dirname(os.path.abspath(__file__))
LOCK = threading.Lock()


class Demo:
    """Holds two live sessions and, optionally, an attacker sitting between them."""

    def __init__(self):
        self.reset(mitm=False)

    # ---------- session setup ----------
    def reset(self, mitm=False, preserve_results=False):
        if not preserve_results or not hasattr(self, "results"):
            self.results = {}
        self.mitm = mitm
        self.events = []          # everything the UI renders
        self.seq = 0
        self.last_record = None   # for the replay button
        self.last_experiment = None

        a_priv, a_pub = generate_keypair()
        b_priv, b_pub = generate_keypair()
        self.a_raw, self.b_raw = serialise_public(a_pub), serialise_public(b_pub)

        if not mitm:
            a_s, a_r, _ = derive_session_keys(a_priv, deserialise_public(self.b_raw), True)
            b_s, b_r, _ = derive_session_keys(b_priv, deserialise_public(self.a_raw), False)
            self.alice = SecureSession(a_s, a_r)
            self.bob = SecureSession(b_s, b_r)
            self.mal_a = self.mal_b = None
            self.fp_alice = self.fp_bob = fingerprint(self.a_raw, self.b_raw)
        else:
            # Mallory runs a separate DH with each side.
            m1_priv, m1_pub = generate_keypair()
            m2_priv, m2_pub = generate_keypair()
            m1_raw, m2_raw = serialise_public(m1_pub), serialise_public(m2_pub)

            a_s, a_r, _ = derive_session_keys(a_priv, deserialise_public(m1_raw), True)
            ma_s, ma_r, _ = derive_session_keys(m1_priv, deserialise_public(self.a_raw), False)
            mb_s, mb_r, _ = derive_session_keys(m2_priv, deserialise_public(self.b_raw), True)
            b_s, b_r, _ = derive_session_keys(b_priv, deserialise_public(m2_raw), False)

            self.alice = SecureSession(a_s, a_r)
            self.mal_a = SecureSession(ma_s, ma_r)   # faces Alice
            self.mal_b = SecureSession(mb_s, mb_r)   # faces Bob
            self.bob = SecureSession(b_s, b_r)
            self.fp_alice = fingerprint(self.a_raw, m1_raw)
            self.fp_bob = fingerprint(m2_raw, self.b_raw)

        self._log("system", "Handshake complete. "
                  + ("ATTACKER ACTIVE: Mallory completed a separate exchange with each side."
                     if mitm else "Two public values crossed the wire. Keys never did."))

    # ---------- helpers ----------
    def _log(self, kind, text, **extra):
        self.seq += 1
        ev = {"id": self.seq, "kind": kind, "text": text}
        ev.update(extra)
        self.events.append(ev)
        return ev

    def state(self):
        return {
            "events": self.events[-120:],
            "mitm": self.mitm,
            "fp_alice": self.fp_alice,
            "fp_bob": self.fp_bob,
            "fp_match": self.fp_alice == self.fp_bob,
            "results": self.results,
            "last_experiment": self.last_experiment,
        }

    def _result(self, key, status, verdict, detail, evidence):
        self.last_experiment = key
        self.results[key] = {
            "status": status,
            "verdict": verdict,
            "detail": detail,
            "evidence": evidence,
        }

    # ---------- actions ----------
    def send(self, who, text):
        if who not in ("alice", "bob"):
            raise ValueError("who must be alice or bob")
        text = (text or "").strip()
        if not text:
            return
        sender = self.alice if who == "alice" else self.bob
        other = "bob" if who == "alice" else "alice"

        record = sender.encrypt(text.encode())
        self.last_record = (who, record)

        self._log("plain", text, who=who)
        self._log("wire", record.hex(), length=len(record),
                  counter=int.from_bytes(record[:8], "big"),
                  direction="A to B" if who == "alice" else "B to A")

        if self.mitm:
            # Mallory decrypts, reads, and re-encrypts under the other key.
            mal_in = self.mal_a if who == "alice" else self.mal_b
            mal_out = self.mal_b if who == "alice" else self.mal_a
            stolen = mal_in.decrypt(record).decode()
            self._log("intercept", stolen)
            record = mal_out.encrypt(stolen.encode())

        receiver = self.bob if who == "alice" else self.alice
        try:
            self._log("plain", receiver.decrypt(record).decode(), who=other, received=True)
        except InvalidTag:
            self._log("reject", "authentication failed, message dropped")
        except ReplayError as e:
            self._log("reject", f"replay blocked: {e}")

    def attack_tamper(self):
        """Flip one bit in a fresh record and offer it to Bob."""
        msg = b"transfer $100 to account 12345"
        rec = bytearray(self.alice.encrypt(msg))
        idx = 20 if len(rec) > 20 else len(rec) - 1
        before = rec[idx]
        rec[idx] ^= 0x01
        self._log("attack", f"Flipped one bit in a ciphertext byte "
                            f"(0x{before:02x} to 0x{rec[idx]:02x}). Offering it to Bob.")
        try:
            self.bob.decrypt(bytes(rec))
            self._log("bad", "Bob ACCEPTED a modified message. Integrity has failed.")
            self._result("tamper", "fail", "Unexpected failure",
                         "Bob accepted a modified ciphertext.", "Modified record delivered")
        except InvalidTag:
            self._log("good", "Bob rejected it. InvalidTag raised, message never shown. "
                              "The GCM tag covers the ciphertext, so any edit is detected.")
            self._result("tamper", "pass", "Defended",
                         "A one bit ciphertext edit is rejected before plaintext is shown.",
                         "cryptography.exceptions.InvalidTag")
        except ReplayError as e:
            self._log("good", f"Rejected before tag check: {e}")
            self._result("tamper", "pass", "Defended",
                         "The modified record was rejected before delivery.", str(e))

    def attack_counter(self):
        """Rewrite the clear counter and prove that AAD authenticates it."""
        self.reset(mitm=False, preserve_results=True)
        rec = bytearray(self.alice.encrypt(b"message one"))
        original = int.from_bytes(rec[:8], "big")
        rec[7] = 0x09
        changed = int.from_bytes(rec[:8], "big")
        self._log("attack", f"Changed the clear counter from {original} to {changed}. "
                            "Bob now checks the record.")
        try:
            self.bob.decrypt(bytes(rec))
            self._log("bad", "Bob accepted the changed counter. Integrity failed.")
            self._result("counter", "fail", "Unexpected failure",
                         "Bob accepted a changed counter.", "Counter edit accepted")
        except InvalidTag:
            self._log("good", "Bob rejected the record. The counter is clear but it is "
                              "authenticated as additional data.")
            self._result("counter", "pass", "Defended",
                         "Changing the clear counter invalidates the GCM tag.",
                         f"counter {original} changed to {changed}, then InvalidTag")

    def attack_replay(self):
        if not self.last_record:
            self.send("alice", "unlock the front door")
        who, rec = self.last_record
        self._log("attack", "Captured the previous record and re-sent it unchanged. "
                            "Note it is perfectly authentic, so the tag will verify.")
        receiver = self.bob if who == "alice" else self.alice
        try:
            receiver.decrypt(rec)
            self._log("bad", "Replay ACCEPTED. The message was delivered twice.")
            self._result("replay", "fail", "Unexpected failure",
                         "A captured record was delivered twice.", "Repeated record accepted")
        except ReplayError as e:
            self._log("good", f"Blocked: {e}. Stopped by protocol state, not by the "
                              "cipher. An authentic message can still be stale.")
            self._result("replay", "pass", "Defended",
                         "A valid captured record cannot be delivered twice.", str(e))
        except InvalidTag:
            self._log("good", "Rejected at tag check.")
            self._result("replay", "pass", "Defended",
                         "The repeated record was rejected.", "InvalidTag")

    def run_experiment(self, kind):
        """Run the same claims exposed by the terminal demonstrations."""
        if kind == "passive":
            self.reset(mitm=False, preserve_results=True)
            message = "The project key stays with Alice and Bob"
            self.send("alice", message)
            _, record = self.last_record
            hidden = message.encode() not in record
            self._result("passive", "pass" if hidden else "fail",
                         "Defended" if hidden else "Unexpected failure",
                         "The relay receives a counter, ciphertext and tag, while Bob recovers the message.",
                         f"{len(record)} wire bytes, plaintext absent from record")
        elif kind == "tamper":
            self.reset(mitm=False, preserve_results=True)
            self.attack_tamper()
        elif kind == "counter":
            self.attack_counter()
        elif kind == "replay":
            self.reset(mitm=False, preserve_results=True)
            self.send("alice", "unlock the front door")
            self.attack_replay()
        elif kind == "mitm":
            self.reset(mitm=True, preserve_results=True)
            secret = "The meeting is at 4 pm, bring the documents"
            self.send("alice", secret)
            self._result("mitm", "exposed", "Known weakness",
                         "Mallory establishes one key with Alice and another with Bob, then reads the message.",
                         "Safety numbers differ and Mallory recovers the full plaintext")
        elif kind == "metadata":
            self.reset(mitm=False, preserve_results=True)
            messages = ["hi", "can you talk", "no",
                        "I am resigning on Monday and taking the client list with me"]
            lengths = []
            for message in messages:
                self.send("alice", message)
                lengths.append(len(self.last_record[1]))
            pairs = ", ".join(f"{len(m.encode())} to {n}" for m, n in zip(messages, lengths))
            self._result("metadata", "exposed", "Known weakness",
                         "The relay cannot read content but exact plaintext length remains visible.",
                         f"plaintext bytes to wire bytes: {pairs}")
        elif kind == "nonce":
            key = AESGCM.generate_key(bit_length=256)
            aead = AESGCM(key)
            nonce = b"\x00" * 12
            p1 = b"transfer 100 dollars to alice00"
            p2 = b"transfer 900 dollars to mallory"
            c1 = aead.encrypt(nonce, p1, None)[:-16]
            c2 = aead.encrypt(nonce, p2, None)[:-16]
            xor_ct = bytes(a ^ b for a, b in zip(c1, c2))
            recovered = bytes(a ^ b for a, b in zip(xor_ct, p1))
            worked = recovered == p2
            self._result("nonce", "exposed" if worked else "fail", "Catastrophic if reused",
                         "Deliberately reusing one GCM nonce lets an attacker recover a second message.",
                         f"Recovered plaintext: {recovered.decode()}")
        elif kind == "params":
            from mpmath import mp
            from sympy import isprime
            mp.dps = 700
            floor_term = int(mp.floor(mp.mpf(2) ** 1918 * mp.pi))
            computed = 2 ** 2048 - 2 ** 1984 - 1 + 2 ** 64 * (floor_term + 124476)
            checks = (computed == RFC3526_GROUP14_P and
                      RFC3526_GROUP14_G == 2 and
                      isprime(RFC3526_GROUP14_P) and
                      isprime((RFC3526_GROUP14_P - 1) // 2))
            self._result("params", "pass" if checks else "fail",
                         "Verified" if checks else "Verification failed",
                         "The group constant matches the RFC formula and both p and q are prime.",
                         "2048 bits, generator 2, formula true, p prime, q prime")
        elif kind == "tests":
            start_dir = os.path.join(HERE, "..", "tests")
            suite = unittest.defaultTestLoader.discover(start_dir)
            stream = io.StringIO()
            result = unittest.TextTestRunner(stream=stream, verbosity=0).run(suite)
            passed = result.wasSuccessful()
            self._result("tests", "pass" if passed else "fail",
                         "All tests pass" if passed else "Tests failed",
                         "The browser invoked the same unittest suite used in the terminal evidence.",
                         f"{result.testsRun - len(result.failures) - len(result.errors)} of {result.testsRun} passed")
        else:
            raise ValueError("unknown experiment")


DEMO = Demo()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass                                   # keep the console quiet

    def _send(self, code, body, ctype="application/json"):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            with open(os.path.join(HERE, "index.html"), "rb") as fh:
                return self._send(200, fh.read(), "text/html; charset=utf-8")
        if self.path == "/api/state":
            with LOCK:
                return self._send(200, json.dumps(DEMO.state()))
        self._send(404, json.dumps({"error": "not found"}))

    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
            if n > 1 << 20:
                return self._send(413, json.dumps({"error": "request is too large"}))
            payload = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return self._send(400, json.dumps({"error": "bad json"}))

        with LOCK:
            if self.path == "/api/send":
                try:
                    DEMO.send(payload.get("who", "alice"), payload.get("text", ""))
                except ValueError as exc:
                    return self._send(400, json.dumps({"error": str(exc)}))
            elif self.path == "/api/reset":
                DEMO.reset(mitm=bool(payload.get("mitm")),
                           preserve_results=bool(payload.get("preserve_results")))
            elif self.path == "/api/attack":
                kind = payload.get("kind")
                if kind == "tamper":
                    DEMO.attack_tamper()
                elif kind == "replay":
                    DEMO.attack_replay()
                else:
                    return self._send(400, json.dumps({"error": "unknown attack"}))
            elif self.path == "/api/experiment":
                try:
                    DEMO.run_experiment(payload.get("kind"))
                except ValueError as exc:
                    return self._send(400, json.dumps({"error": str(exc)}))
            else:
                return self._send(404, json.dumps({"error": "not found"}))
            return self._send(200, json.dumps(DEMO.state()))


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = f"http://127.0.0.1:{port}"
    print(f"E2EE inspector running at {url}")
    print("This is a viewer over src/crypto_core.py. No cryptography is reimplemented here.")
    print("Press Ctrl+C to stop.")
    try:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    except Exception:
        pass
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")


if __name__ == "__main__":
    main()
