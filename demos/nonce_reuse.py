"""
nonce_reuse.py  -  why the counter design matters.

I claimed in the design that nonces must never repeat under one key.
Rather than assert that, here is the actual damage, measured.

GCM is CTR mode underneath. Same key + same nonce = same keystream.
Two ciphertexts under one keystream give C1 xor C2 = P1 xor P2, which
removes the key from the equation entirely.

Run: python3 demos/nonce_reuse.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

key = AESGCM.generate_key(bit_length=256)
aead = AESGCM(key)

BAD_NONCE = b"\x00" * 12          # deliberately reused

p1 = b"transfer 100 dollars to alice00"
p2 = b"transfer 900 dollars to mallory"

c1 = aead.encrypt(BAD_NONCE, p1, None)
c2 = aead.encrypt(BAD_NONCE, p2, None)

print("=" * 74)
print("NONCE REUSE - what happens if the counter repeats")
print("=" * 74)
print(f"key      : {key.hex()[:32]}... (attacker does NOT have this)")
print(f"nonce    : {BAD_NONCE.hex()}  (reused for both messages)")
print()

# strip the 16 byte GCM tag to get the raw CTR ciphertext
b1, b2 = c1[:-16], c2[:-16]
xor_ct = bytes(x ^ y for x, y in zip(b1, b2))
xor_pt = bytes(x ^ y for x, y in zip(p1, p2))

print(f"C1 xor C2 : {xor_ct.hex()}")
print(f"P1 xor P2 : {xor_pt.hex()}")
print(f"identical : {xor_ct == xor_pt}")
print()

# An attacker who guesses/knows one plaintext recovers the other exactly.
recovered = bytes(x ^ y for x, y in zip(xor_ct, p1))
print("Attacker knows or guesses P1 (a common template message):")
print(f"  known    P1 = {p1.decode()}")
print(f"  RECOVERED P2 = {recovered.decode()}")
print(f"  correct?     = {recovered == p2}")
print()
print("RESULT: the key was never broken and never needed to be. Reusing one")
print("        nonce leaks the XOR of both plaintexts, and one known message")
print("        peels off the other in full. GCM additionally loses its")
print("        authentication guarantee under nonce reuse (the tag key can be")
print("        recovered), so forgery becomes possible too.")
print()
print("This is why crypto_core.SecureSession derives SEPARATE keys per")
print("direction and uses a strict per key counter: if both parties encrypted")
print("with one shared key starting at counter 0, their first messages would")
print("collide on (key, nonce) immediately and reproduce exactly this failure.")
