"""
test_crypto.py  -  test suite for the E2EE core.

Covers correctness (both sides agree, round trips work) and the security
properties I claim in the report (tamper detection, replay blocking,
small subgroup rejection, key separation, nonce uniqueness).

Run: python3 -m pytest tests/ -v      or      python3 tests/test_crypto.py
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from crypto_core import (generate_keypair, serialise_public, deserialise_public,
                         derive_session_keys, fingerprint, SecureSession,
                         ReplayError, HandshakeError, RFC3526_GROUP14_P)
from cryptography.exceptions import InvalidTag


def handshake_pair():
    a_priv, a_pub = generate_keypair()
    b_priv, b_pub = generate_keypair()
    a_raw, b_raw = serialise_public(a_pub), serialise_public(b_pub)
    a_s, a_r, sh_a = derive_session_keys(a_priv, deserialise_public(b_raw), True)
    b_s, b_r, sh_b = derive_session_keys(b_priv, deserialise_public(a_raw), False)
    return (SecureSession(a_s, a_r), SecureSession(b_s, b_r),
            sh_a, sh_b, a_raw, b_raw, a_s, a_r, b_s, b_r)


class TestKeyExchange(unittest.TestCase):

    def test_shared_secret_agrees(self):
        _, _, sh_a, sh_b, *_ = handshake_pair()
        self.assertEqual(sh_a, sh_b)

    def test_independent_sessions_differ(self):
        _, _, sh1, _, *_ = handshake_pair()
        _, _, sh2, _, *_ = handshake_pair()
        self.assertNotEqual(sh1, sh2, "ephemeral keys must give fresh secrets")

    def test_direction_keys_are_separate(self):
        *_, a_s, a_r, b_s, b_r = handshake_pair()
        self.assertNotEqual(a_s, a_r, "send and recv keys must differ")
        self.assertEqual(a_s, b_r, "Alice send must equal Bob recv")
        self.assertEqual(a_r, b_s, "Alice recv must equal Bob send")

    def test_public_key_is_256_bytes(self):
        _, pub = generate_keypair()
        self.assertEqual(len(serialise_public(pub)), 256)

    def test_rejects_small_subgroup_values(self):
        for bad in (0, 1, RFC3526_GROUP14_P - 1):
            with self.assertRaises(HandshakeError):
                deserialise_public(bad.to_bytes(256, "big"))

    def test_rejects_wrong_length(self):
        with self.assertRaises(HandshakeError):
            deserialise_public(b"\x01" * 128)

    def test_fingerprint_is_symmetric(self):
        _, _, _, _, a_raw, b_raw, *_ = handshake_pair()
        self.assertEqual(fingerprint(a_raw, b_raw), fingerprint(b_raw, a_raw))

    def test_fingerprint_changes_with_different_key(self):
        _, _, _, _, a_raw, b_raw, *_ = handshake_pair()
        _, other = generate_keypair()
        self.assertNotEqual(fingerprint(a_raw, b_raw),
                            fingerprint(a_raw, serialise_public(other)))


class TestRecordLayer(unittest.TestCase):

    def test_round_trip(self):
        alice, bob, *_ = handshake_pair()
        for msg in [b"", b"a", b"hello world", os.urandom(4096)]:
            self.assertEqual(bob.decrypt(alice.encrypt(msg)), msg)

    def test_ciphertext_differs_from_plaintext(self):
        alice, bob, *_ = handshake_pair()
        msg = b"secret message here"
        self.assertNotIn(msg, alice.encrypt(msg))

    def test_same_plaintext_gives_different_ciphertext(self):
        alice, bob, *_ = handshake_pair()
        c1, c2 = alice.encrypt(b"repeat"), alice.encrypt(b"repeat")
        self.assertNotEqual(c1, c2, "counter must make records unique")

    def test_tamper_detected(self):
        alice, bob, *_ = handshake_pair()
        rec = bytearray(alice.encrypt(b"pay alice 100"))
        rec[15] ^= 0x01
        with self.assertRaises(InvalidTag):
            bob.decrypt(bytes(rec))

    def test_truncation_detected(self):
        alice, bob, *_ = handshake_pair()
        rec = alice.encrypt(b"important message")
        with self.assertRaises(InvalidTag):
            bob.decrypt(rec[:-1])

    def test_counter_tamper_detected(self):
        alice, bob, *_ = handshake_pair()
        rec = bytearray(alice.encrypt(b"msg"))
        rec[7] = 0x05
        with self.assertRaises(InvalidTag):
            bob.decrypt(bytes(rec))

    def test_replay_blocked(self):
        alice, bob, *_ = handshake_pair()
        rec = alice.encrypt(b"unlock door")
        bob.decrypt(rec)
        with self.assertRaises(ReplayError):
            bob.decrypt(rec)

    def test_reorder_blocked(self):
        alice, bob, *_ = handshake_pair()
        r0, r1 = alice.encrypt(b"first"), alice.encrypt(b"second")
        bob.decrypt(r1)
        with self.assertRaises(ReplayError):
            bob.decrypt(r0)

    def test_cross_session_key_isolation(self):
        alice1, _, *_ = handshake_pair()
        _, bob2, *_ = handshake_pair()
        with self.assertRaises(InvalidTag):
            bob2.decrypt(alice1.encrypt(b"wrong session"))

    def test_nonces_unique_over_many_messages(self):
        alice, _, *_ = handshake_pair()
        seen = {alice.encrypt(b"x")[:8] for _ in range(2000)}
        self.assertEqual(len(seen), 2000, "every counter must be unique")


if __name__ == "__main__":
    unittest.main(verbosity=2)
