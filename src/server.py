"""
server.py  -  untrusted relay.

This server is deliberately DUMB. It pairs two clients and copies bytes
between them. It never holds a key and never sees plaintext.

It also logs every byte it relays. That log is the evidence for the core
claim of the project: a compromised server sees ciphertext only.

Run:  python3 server.py [port]
"""

import socket
import socketserver
import struct
import sys
import threading
import datetime

HOST, PORT = "127.0.0.1", 9009
LOGFILE = "evidence/server_view.log"

_waiting = []          # clients waiting to be paired
_lock = threading.Lock()


def log(msg: str):
    line = f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    try:
        with open(LOGFILE, "a") as fh:
            fh.write(line + "\n")
    except OSError:
        pass


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def recv_frame(sock):
    """Length prefixed frame: 4 byte big endian length || payload."""
    hdr = recv_exact(sock, 4)
    if hdr is None:
        return None
    (n,) = struct.unpack(">I", hdr)
    if n > 1 << 20:
        return None
    return recv_exact(sock, n)


def send_frame(sock, payload: bytes):
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def pump(src, dst, label):
    """Copy frames one way, logging exactly what the relay can observe."""
    first_frame = True
    while True:
        try:
            frame = recv_frame(src)
        except OSError:
            break
        if frame is None:
            break
        # Each direction begins with exactly one DH public value. Inferring the
        # record type from length would mislabel a valid 256 byte ciphertext.
        kind = "HANDSHAKE" if first_frame else "CIPHERTEXT"
        first_frame = False
        preview = frame[:32].hex()
        log(f"relay {label} | {kind} | {len(frame):>4} bytes | {preview}...")
        try:
            send_frame(dst, frame)
        except OSError:
            break
    try:
        dst.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass


def handle_pair(a, b):
    log("paired two clients, relaying (server holds no keys)")
    t1 = threading.Thread(target=pump, args=(a, b, "A->B"), daemon=True)
    t2 = threading.Thread(target=pump, args=(b, a, "B->A"), daemon=True)
    t1.start(); t2.start()
    t1.join(); t2.join()
    log("session closed")


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else PORT
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, port))
    srv.listen(8)
    log(f"relay listening on {HOST}:{port}")
    while True:
        conn, addr = srv.accept()
        log(f"connection from {addr[0]}:{addr[1]}")
        with _lock:
            _waiting.append(conn)
            if len(_waiting) >= 2:
                a, b = _waiting.pop(0), _waiting.pop(0)
                threading.Thread(target=handle_pair, args=(a, b), daemon=True).start()


if __name__ == "__main__":
    main()
