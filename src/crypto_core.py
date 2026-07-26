"""
crypto_core.py  -  cryptographic core for the E2EE chat demo.

Design decisions (justified in the report):
  * Finite field Diffie-Hellman, RFC 3526 MODP Group 14 (2048 bit).
  * Raw DH output is NEVER used as a key. It is run through HKDF-SHA256.
  * AES-256-GCM (AEAD) gives confidentiality AND integrity in one primitive.
  * Separate send/recv keys per direction so the two parties can never
    collide on a (key, nonce) pair.
  * Counter based 96 bit nonces. A repeat under one key breaks GCM badly.
  * All primitives come from `cryptography` (OpenSSL backed). No hand rolled maths.

Author: Islam Sharaf (z5592832), COMP6441 project.
"""

import os
import struct
import hashlib

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------------------------------------------------------------------------
# 1. Diffie-Hellman parameters
# ---------------------------------------------------------------------------
# RFC 3526, Section 3: 2048 bit MODP Group (group id 14). Generator g = 2.
# These are FIXED, PUBLIC, standardised parameters. Using a well known group
# means we are not trusting a randomly generated modulus of unknown quality.
RFC3526_GROUP14_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
RFC3526_GROUP14_G = 2

_PN = dh.DHParameterNumbers(RFC3526_GROUP14_P, RFC3526_GROUP14_G)
PARAMETERS = _PN.parameters()

# Domain separation string. Binds derived keys to this protocol + version.
HKDF_INFO = b"COMP6441-e2ee-chat/v1 aes256gcm"


class HandshakeError(Exception):
    pass


class ReplayError(Exception):
    pass


# ---------------------------------------------------------------------------
# 2. Key exchange
# ---------------------------------------------------------------------------
def generate_keypair():
    """Fresh EPHEMERAL DH keypair. Ephemeral => forward secrecy per session."""
    priv = PARAMETERS.generate_private_key()
    return priv, priv.public_key()


def serialise_public(pub) -> bytes:
    """Public key as raw big endian integer bytes (256 bytes for 2048 bit)."""
    y = pub.public_numbers().y
    return y.to_bytes(256, "big")


def deserialise_public(raw: bytes):
    if len(raw) != 256:
        raise HandshakeError(f"bad public key length {len(raw)}")
    y = int.from_bytes(raw, "big")
    # Reject degenerate values. y in {0,1,p-1} forces the shared secret into a
    # tiny subgroup, so an attacker could pin the secret to a known value.
    if y <= 1 or y >= RFC3526_GROUP14_P - 1:
        raise HandshakeError("public key in small subgroup - rejected")
    return dh.DHPublicNumbers(y, _PN).public_key()


def derive_session_keys(private_key, peer_public, initiator: bool):
    """
    DH -> shared secret -> HKDF -> two independent 256 bit AES keys.

    Why HKDF and not the raw secret: the DH output is a group element with
    algebraic structure and biased bits, not a uniform random key. HKDF
    extracts uniform key material and lets us derive TWO keys from one secret.
    """
    shared = private_key.exchange(peer_public)

    okm = HKDF(
        algorithm=hashes.SHA256(),
        length=64,                # 32 bytes per direction
        salt=None,
        info=HKDF_INFO,
    ).derive(shared)

    key_a2b, key_b2a = okm[:32], okm[32:]

    # The initiator sends on A->B and receives on B->A. The responder mirrors.
    if initiator:
        return key_a2b, key_b2a, shared
    return key_b2a, key_a2b, shared


def fingerprint(pub_a: bytes, pub_b: bytes) -> str:
    """
    Signal style 'safety number'. A short human comparable digest of BOTH
    public keys. Sorted so each side computes the same value.

    This is the ONLY defence against an active MITM in this design, and it
    requires an out of band channel (meet up, phone call).
    """
    lo, hi = sorted([pub_a, pub_b])
    digest = hashlib.sha256(lo + hi).digest()
    n = int.from_bytes(digest[:15], "big")
    s = str(n).zfill(36)[:36]
    return " ".join(s[i:i + 6] for i in range(0, 36, 6))


# ---------------------------------------------------------------------------
# 3. Record layer (AES-256-GCM)
# ---------------------------------------------------------------------------
class SecureSession:
    """
    Encrypts/decrypts messages after the handshake.

    Nonce construction: 4 zero bytes || 8 byte big endian counter.
    The counter increments per message and never repeats under one key.
    Receiver tracks the highest seen counter and refuses anything <= it,
    which blocks replay and reordering.
    """

    def __init__(self, send_key: bytes, recv_key: bytes):
        self._send = AESGCM(send_key)
        self._recv = AESGCM(recv_key)
        self._send_ctr = 0
        self._recv_high = -1

    @staticmethod
    def _nonce(counter: int) -> bytes:
        return b"\x00\x00\x00\x00" + struct.pack(">Q", counter)

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        ctr = self._send_ctr
        self._send_ctr += 1
        # Counter is authenticated as AAD so an attacker cannot renumber records.
        header = struct.pack(">Q", ctr)
        ct = self._send.encrypt(self._nonce(ctr), plaintext, header + aad)
        return header + ct

    def decrypt(self, record: bytes, aad: bytes = b"") -> bytes:
        if len(record) < 8:
            raise ReplayError("truncated record")
        header, ct = record[:8], record[8:]
        ctr = struct.unpack(">Q", header)[0]
        if ctr <= self._recv_high:
            raise ReplayError(f"replay/reorder detected (counter {ctr})")
        # Raises InvalidTag if ciphertext, counter or AAD was modified.
        pt = self._recv.decrypt(self._nonce(ctr), ct, header + aad)
        self._recv_high = ctr
        return pt
