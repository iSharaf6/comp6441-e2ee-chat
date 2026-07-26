"""Verify the DH constant against RFC 3526 rather than trusting a copy paste."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
from crypto_core import RFC3526_GROUP14_P as p, RFC3526_GROUP14_G as g
from mpmath import mp, mpf, pi as mppi
from sympy import isprime

mp.dps = 700
floor_term = int(mp.floor(mp.mpf(2)**1918 * mppi))
computed = 2**2048 - 2**1984 - 1 + 2**64 * (floor_term + 124476)

print("Verifying DH parameters against RFC 3526 Section 3 (Group 14)")
print("-" * 62)
print(f"p bit length            : {p.bit_length()}")
print(f"matches RFC 3526 formula: {computed == p}")
print(f"generator g             : {g}")
print(f"p is prime              : {isprime(p)}")
print(f"(p-1)/2 is prime        : {isprime((p-1)//2)}  <- safe prime")
print("-" * 62)
print("A safe prime means the only small subgroup is order 2, so the")
print("small subgroup check in deserialise_public() is sufficient.")
