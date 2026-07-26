"""
client.py  -  end to end encrypted chat client.

Protocol:
  1. Both sides generate an ephemeral DH keypair and send the public key.
  2. Both derive the same shared secret, run it through HKDF, and get
     two AES-256-GCM keys (one per direction).
  3. Every message is a GCM record with an authenticated counter.

The relay in the middle sees only step 1 public values and step 3 ciphertext.

Run:  python3 client.py <name> [--initiator] [--port N]
"""

import argparse
import socket
import struct
import sys
import threading

sys.path.insert(0, __import__("os").path.dirname(__file__))
from crypto_core import (generate_keypair, serialise_public, deserialise_public,
                         derive_session_keys, fingerprint, SecureSession,
                         ReplayError)
from cryptography.exceptions import InvalidTag


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        c = sock.recv(n - len(buf))
        if not c:
            return None
        buf += c
    return buf


def recv_frame(sock):
    hdr = recv_exact(sock, 4)
    if hdr is None:
        return None
    (n,) = struct.unpack(">I", hdr)
    if n > 1 << 20:
        raise ValueError("frame exceeds 1 MiB limit")
    return recv_exact(sock, n)


def send_frame(sock, payload):
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def handshake(sock, initiator: bool):
    priv, pub = generate_keypair()
    mine = serialise_public(pub)
    send_frame(sock, mine)
    theirs = recv_frame(sock)
    if theirs is None:
        raise SystemExit("peer disconnected during handshake")
    peer_pub = deserialise_public(theirs)
    send_key, recv_key, shared = derive_session_keys(priv, peer_pub, initiator)
    return SecureSession(send_key, recv_key), fingerprint(mine, theirs), shared


def reader(sock, session, name):
    while True:
        frame = recv_frame(sock)
        if frame is None:
            print("\n[peer disconnected]")
            return
        try:
            pt = session.decrypt(frame)
            print(f"\n[peer] {pt.decode()}\n{name}> ", end="", flush=True)
        except InvalidTag:
            print("\n[!] AUTHENTICATION FAILED - message tampered, dropped"
                  f"\n{name}> ", end="", flush=True)
        except ReplayError as e:
            print(f"\n[!] REPLAY BLOCKED - {e}\n{name}> ", end="", flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("name")
    ap.add_argument("--initiator", action="store_true")
    ap.add_argument("--port", type=int, default=9009)
    args = ap.parse_args()

    sock = socket.create_connection(("127.0.0.1", args.port))
    session, fp, _ = handshake(sock, args.initiator)

    print(f"[{args.name}] secure channel established (AES-256-GCM)")
    print(f"[{args.name}] SAFETY NUMBER: {fp}")
    print(f"[{args.name}] verify this out of band or you are not MITM safe\n")

    threading.Thread(target=reader, args=(sock, session, args.name),
                     daemon=True).start()
    try:
        while True:
            line = input(f"{args.name}> ")
            if line.strip() in ("/quit", "/exit"):
                break
            send_frame(sock, session.encrypt(line.encode()))
    except (EOFError, KeyboardInterrupt):
        pass
    sock.close()


if __name__ == "__main__":
    main()
