"""
attacks.py  -  I attack my own design.

Six experiments:
  A. Passive eavesdropper       (should fail)
  B. Message tampering          (should be detected)
  B2. Counter renumbering       (should be detected)
  C. Replay                     (should be blocked)
  D. Active MITM on the handshake (SUCCEEDS - this is the real weakness)
  E. Metadata leakage           (SUCCEEDS - not defended at all)

Run: python3 demos/attacks.py
"""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from crypto_core import (generate_keypair, serialise_public, deserialise_public,
                         derive_session_keys, fingerprint, SecureSession,
                         ReplayError, HandshakeError)
from cryptography.exceptions import InvalidTag


def rule(title):
    print("\n" + "=" * 74)
    print(title)
    print("=" * 74)


def make_pair():
    """Honest handshake between Alice and Bob."""
    a_priv, a_pub = generate_keypair()
    b_priv, b_pub = generate_keypair()
    a_raw, b_raw = serialise_public(a_pub), serialise_public(b_pub)
    a_send, a_recv, _ = derive_session_keys(a_priv, deserialise_public(b_raw), True)
    b_send, b_recv, _ = derive_session_keys(b_priv, deserialise_public(a_raw), False)
    return (SecureSession(a_send, a_recv), SecureSession(b_send, b_recv),
            fingerprint(a_raw, b_raw))


# ---------------------------------------------------------------- A
def demo_eavesdrop():
    rule("EXPERIMENT A - passive eavesdropper on the wire")
    alice, bob, _ = make_pair()
    msg = b"my bank password is hunter2"
    rec = alice.encrypt(msg)
    print(f"Alice sends plaintext : {msg.decode()}")
    print(f"Eve observes on wire  : {rec.hex()}")
    print(f"Eve tries ASCII decode: {rec.decode('ascii', errors='replace')[:60]!r}")
    print(f"Bob decrypts to       : {bob.decrypt(rec).decode()}")
    print("\nRESULT: Eve gets ciphertext only. Confidentiality holds against a")
    print("        passive attacker. This is the easy case.")


# ---------------------------------------------------------------- B
def demo_tamper():
    rule("EXPERIMENT B - active attacker flips one bit in the ciphertext")
    alice, bob, _ = make_pair()
    rec = bytearray(alice.encrypt(b"transfer $100 to account 12345"))
    victim = 20
    print(f"original byte[{victim}] = 0x{rec[victim]:02x}")
    rec[victim] ^= 0x01                      # single bit flip
    print(f"flipped  byte[{victim}] = 0x{rec[victim]:02x}  (one bit changed)")
    try:
        bob.decrypt(bytes(rec))
        print("RESULT: FAILURE - tampering was accepted")
    except InvalidTag:
        print("\nBob raises InvalidTag -> message rejected, never shown to user.")
        print("RESULT: integrity holds. GCM's tag covers the ciphertext, so any")
        print("        modification is detected. Note this is exactly what plain")
        print("        AES-CTR or AES-CBC would NOT give me - encryption alone is")
        print("        not integrity.")


def demo_tamper_header():
    rule("EXPERIMENT B2 - attacker renumbers the record (attacks the counter)")
    alice, bob, _ = make_pair()
    rec = bytearray(alice.encrypt(b"message one"))
    print(f"counter in header = {int.from_bytes(rec[:8],'big')}")
    rec[7] = 0x09                             # rewrite counter to 9
    print(f"attacker rewrites counter to {int.from_bytes(rec[:8],'big')}")
    try:
        bob.decrypt(bytes(rec))
        print("RESULT: FAILURE - renumbering accepted")
    except InvalidTag:
        print("\nRESULT: rejected. The counter is passed as AAD, so it is")
        print("        authenticated even though it travels in clear. If I had")
        print("        left it unauthenticated an attacker could reorder or")
        print("        suppress messages silently.")


# ---------------------------------------------------------------- C
def demo_replay():
    rule("EXPERIMENT C - attacker captures a record and re-sends it")
    alice, bob, _ = make_pair()
    rec = alice.encrypt(b"unlock the front door")
    print(f"Bob first delivery : {bob.decrypt(rec).decode()!r}  (accepted)")
    try:
        bob.decrypt(rec)
        print("RESULT: FAILURE - replay accepted, door unlocked twice")
    except ReplayError as e:
        print(f"Bob second delivery: rejected - {e}")
        print("\nRESULT: replay blocked by the monotonic counter. Worth noting the")
        print("        AEAD tag alone would NOT have caught this - a replayed")
        print("        record is perfectly authentic. Replay defence is protocol")
        print("        level state, not a property of the cipher.")


# ---------------------------------------------------------------- D
def demo_mitm():
    rule("EXPERIMENT D - active MITM on an UNAUTHENTICATED handshake")
    print("Mallory sits on the relay and answers each side herself.\n")

    a_priv, a_pub = generate_keypair()
    b_priv, b_pub = generate_keypair()
    m_priv1, m_pub1 = generate_keypair()      # Mallory's key facing Alice
    m_priv2, m_pub2 = generate_keypair()      # Mallory's key facing Bob

    a_raw, b_raw = serialise_public(a_pub), serialise_public(b_pub)
    m1_raw, m2_raw = serialise_public(m_pub1), serialise_public(m_pub2)

    # Alice believes she is talking to Bob; she actually shares a key with Mallory
    a_send, a_recv, _ = derive_session_keys(a_priv, deserialise_public(m1_raw), True)
    ma_send, ma_recv, _ = derive_session_keys(m_priv1, deserialise_public(a_raw), False)
    # Mallory <-> Bob
    mb_send, mb_recv, _ = derive_session_keys(m_priv2, deserialise_public(b_raw), True)
    b_send, b_recv, _ = derive_session_keys(b_priv, deserialise_public(m2_raw), False)

    alice = SecureSession(a_send, a_recv)
    mal_a = SecureSession(ma_send, ma_recv)
    mal_b = SecureSession(mb_send, mb_recv)
    bob = SecureSession(b_send, b_recv)

    secret = b"the meeting is at 4pm, bring the documents"
    rec = alice.encrypt(secret)
    stolen = mal_a.decrypt(rec)
    print(f"Alice sends          : {secret.decode()}")
    print(f"MALLORY READS        : {stolen.decode()}   <-- plaintext, fully readable")

    forged = b"the meeting is CANCELLED, go home"
    bob_gets = bob.decrypt(mal_b.encrypt(forged))
    print(f"Mallory re-encrypts  : {forged.decode()}")
    print(f"Bob receives         : {bob_gets.decode()}")
    print("Bob's AEAD tag check : VALID (he has no way to know)")

    print("\nRESULT: TOTAL COMPROMISE. Plain DH authenticates nothing. Alice")
    print("        proved she can do DH, not that she is Alice. Encryption was")
    print("        never broken - the attacker was simply handed the keys.")

    print("\n--- now the defence: compare safety numbers out of band ---")
    honest = fingerprint(a_raw, b_raw)
    alice_sees = fingerprint(a_raw, m1_raw)
    bob_sees = fingerprint(m2_raw, b_raw)
    print(f"what Alice's screen shows : {alice_sees}")
    print(f"what Bob's screen shows   : {bob_sees}")
    print(f"expected if no attacker   : {honest}")
    print(f"\nAlice == Bob ?  {alice_sees == bob_sees}  -> MISMATCH REVEALS MALLORY")
    print("\nBut note the limit: this only works if the humans actually check,")
    print("over a channel Mallory does not control. The maths cannot force that.")


# ---------------------------------------------------------------- E
def demo_metadata():
    rule("EXPERIMENT E - what the relay still learns (metadata)")
    alice, bob, _ = make_pair()
    msgs = [b"hi", b"can you talk", b"no",
            b"I am resigning on Monday and taking the client list with me"]
    print(f"{'plaintext':<62}{'wire len':>9}")
    print("-" * 74)
    for m in msgs:
        rec = alice.encrypt(m)
        bob.decrypt(rec)
        print(f"{m.decode()[:60]:<62}{len(rec):>9}")
        time.sleep(0.05)
    print("\nRESULT: ATTACK SUCCEEDS. The encrypted payload preserves length and")
    print("        the record adds a fixed 24 bytes, so the relay recovers the")
    print("        plaintext length exactly by subtracting 24. It also sees")
    print("        who talks to whom, when, and how often. A short reply after a")
    print("        long message is visibly a 'no'. My design does not defend this")
    print("        at all, and padding + cover traffic would be the fix.")


if __name__ == "__main__":
    demo_eavesdrop()
    demo_tamper()
    demo_tamper_header()
    demo_replay()
    demo_mitm()
    demo_metadata()
    print("\n" + "=" * 74)
    print("SUMMARY: A, B, B2 and C defended. D and E are real, unfixed weaknesses.")
    print("=" * 74)
