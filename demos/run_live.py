"""Automated two-client live session over the real relay (non-interactive)."""
import subprocess, sys, time, socket, struct, os, threading
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from crypto_core import *
from client import handshake, send_frame, recv_frame

PORT = 9031
srv = subprocess.Popen([sys.executable, "src/server.py", str(PORT)],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
time.sleep(1.2)

a = socket.create_connection(("127.0.0.1", PORT)); time.sleep(0.3)
b = socket.create_connection(("127.0.0.1", PORT)); time.sleep(0.5)

res = {}
def do(sock, init, key):
    res[key] = handshake(sock, init)
ta = threading.Thread(target=do, args=(a, True, 'a')); tb = threading.Thread(target=do, args=(b, False, 'b'))
ta.start(); tb.start(); ta.join(); tb.join()

sess_a, fp_a, sh_a = res['a']; sess_b, fp_b, sh_b = res['b']
print("Alice safety number:", fp_a)
print("Bob   safety number:", fp_b)
print("safety numbers match:", fp_a == fp_b)
print("shared secrets identical:", sh_a == sh_b)
print()
for msg in [b"hey, are we actually encrypted?", b"yes, the relay only sees ciphertext", b"prove it"]:
    rec = sess_a.encrypt(msg)
    print(f"Alice plaintext : {msg.decode()}")
    print(f"  wire bytes    : {rec[:40].hex()}... ({len(rec)} bytes)")
    send_frame(a, rec)
    got = recv_frame(b)
    print(f"Bob  decrypted  : {sess_b.decrypt(got).decode()}\n")
a.close(); b.close(); time.sleep(0.6); srv.terminate()
out,_ = srv.communicate(timeout=5)
print("=== WHAT THE SERVER SAW ===")
print(out)
