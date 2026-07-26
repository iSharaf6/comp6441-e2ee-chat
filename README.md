# End to End Encrypted Chat

**COMP6441 Security Engineering · UNSW 2026 T2**
Islam Sharaf · z5592832

A two party end to end encrypted chat application, built to understand *why* each
cryptographic design choice is secure rather than just to make one work. The relay server
in the middle only ever sees ciphertext, and this repository proves that rather than
asserting it.

**If you are marking this and want the short version:** follow
[Step 1](#step-1-install-it) then [Step 2](#step-2-the-fastest-way-to-see-it-work).
That is two commands and one web page, and it demonstrates the entire project including
the attacks. Everything after that is optional detail.

---

## Contents

- [What this project actually is](#what-this-project-actually-is)
- [Step 1: install it](#step-1-install-it)
- [Step 2: the fastest way to see it work](#step-2-the-fastest-way-to-see-it-work)
- [Step 3: the real chat, in three terminals](#step-3-the-real-chat-in-three-terminals)
- [Step 4: running the evidence from the command line](#step-4-running-the-evidence-from-the-command-line)
- [What it does and does not protect](#what-it-does-and-does-not-protect)
- [How it works](#how-it-works)
- [Repository layout](#repository-layout)
- [Troubleshooting](#troubleshooting)
- [Ethics](#ethics)

---

## What this project actually is

Two people, Alice and Bob, want to talk privately. Their messages travel through a
**relay server** in the middle, the same way a real messaging app's servers carry messages
between phones.

The question the project asks is: **how much can that server in the middle see?**

- With ordinary transport encryption (the padlock in a browser), the server *can* read
  everything. It decrypts your message, handles it, and encrypts it again to pass on.
- With **end to end encryption**, only Alice and Bob hold the keys. The server carries
  sealed envelopes it cannot open.

This project builds the second kind, then attacks it six different ways to find out
exactly where the protection stops. Two of those attacks succeed. They are documented here
rather than hidden, because that is the honest and more interesting result.

### Do not use this for real communication

This is a learning artefact, not a product. It has **two known, unfixed weaknesses**:

1. **No endpoint authentication.** An active attacker who sits in the initial handshake
   gets both keys and reads everything. Plain Diffie-Hellman proves the other side can do
   the maths, but not *who they are*. Safety numbers let users detect this, but only if
   they actually compare them.
2. **No metadata protection.** Message lengths, timing and who talked to whom are fully
   visible to the relay.

For real secure messaging, use [Signal](https://signal.org).

---

## Step 1: install it

You need **Python 3.9 or newer**. To check, open a terminal and run:

```bash
python3 --version
```

If that prints 3.9 or higher, you are fine. If the command is not found, install Python
from [python.org/downloads](https://www.python.org/downloads/).

Then run these, one block at a time:

```bash
git clone https://github.com/iSharaf6/comp6441-e2ee-chat.git
cd comp6441-e2ee-chat
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

On **Windows**, replace `source venv/bin/activate` with `venv\Scripts\activate`.

`python3 -m venv venv` creates a private folder for this project's dependencies so nothing
is installed system wide. Once it is active your prompt shows `(venv)`. If you open a new
terminal later, run `source venv/bin/activate` again from inside the project folder before
running anything below.

---

## Step 2: the fastest way to see it work

```bash
python3 web/demo_server.py
```

Then open **http://127.0.0.1:8000** in a browser. It should open by itself.

You will see three columns. **Alice** on the left and **Bob** on the right are the two
people, and both can read everything. The **dark column in the middle is the relay
server**, and it shows literally everything that server is able to see.

Do these four things, in order:

1. **Press Send under Alice.** The message appears as normal readable text in both Alice's
   and Bob's columns. In the dark middle column the same message appears only as a counter
   and a long block of hexadecimal. That block is all the server gets. This is the whole
   point of the project in one screen.

2. **Read the coloured bar above the columns.** It shows a **safety number**, a code Alice
   and Bob each calculate independently from the key exchange. If both sides calculate the
   same number, nobody is impersonating either of them, and the bar is green.

3. **Press "Run all nine checks".** Each row runs the real Python experiment and prints
   the actual evidence it produced. Four checks defend successfully. Three report as
   weaknesses, and **that red result is the correct and expected outcome**, because those
   are the documented limitations. The other two verify the cryptographic parameters and
   run the 18 automated tests.

4. **Look at check D, "Machine in the middle".** After it runs, the bar at the top turns
   red, the two safety numbers no longer match, and the middle column shows an attacker
   called Mallory reading the message in plain text. Alice and Bob still see a completely
   normal conversation. That is the most important finding in the project: encrypting
   perfectly does not prove *who* is on the other end.

Press `Ctrl+C` in the terminal to stop the server when you are done.

> **This web page is a viewer, not a second implementation.** Every key exchange and every
> encryption it displays is a call into `src/crypto_core.py`, the exact same Python module
> the terminal chat uses. Nothing cryptographic is rewritten in JavaScript. If the
> cryptography were broken, this page would break with it.

---

## Step 3: the real chat, in three terminals

This is the actual chat application. The web page above is a window onto the same code.

You need **three terminal windows**, all in the project folder, all with the virtual
environment activated (`source venv/bin/activate`).

```bash
# terminal 1: the untrusted relay
python3 src/server.py
```

```bash
# terminal 2: Alice
python3 src/client.py Alice --initiator
```

```bash
# terminal 3: Bob
python3 src/client.py Bob
```

Type a message into Alice's terminal and press Enter. It appears in Bob's terminal.

**Now look at terminal 1.** The relay prints only `CIPHERTEXT` records with byte counts
and hexadecimal. It never prints a readable word, because it holds no keys.

**Compare the safety numbers.** Both clients print a `SAFETY NUMBER` when they connect,
and the two should be identical. If they ever differ, someone is sitting in the middle.
Comparing them is the only defence this system has against an active attacker, and it only
works over a channel the attacker does not control, such as reading them aloud in person.

Press `Ctrl+C` in each terminal to stop.

---

## Step 4: running the evidence from the command line

Each command runs on its own and prints its own findings. No arguments needed. These are
the same experiments the web page runs.

| Command | What it does | What you should see |
|---|---|---|
| `python3 tests/test_crypto.py` | 18 automated tests of correctness and security properties | `Ran 18 tests ... OK` |
| `python3 tests/verify_params.py` | Recomputes the Diffie-Hellman prime from the RFC 3526 formula instead of trusting the copied constant | every check `True`, confirms a safe prime |
| `python3 demos/attacks.py` | Six adversarial experiments, A through E | four defended, two succeed |
| `python3 demos/nonce_reuse.py` | Shows the damage if one encryption nonce is ever reused | recovers a plaintext without ever having the key |
| `python3 demos/run_live.py` | Automated two client session over the real relay | prints the server's complete view |

Captured output from every one of these is committed under `evidence/`, so you can compare
your run against mine.

**On the two experiments that succeed.** In `demos/attacks.py`, experiment D (machine in
the middle) and experiment E (metadata) are *supposed* to succeed. They are the documented
weaknesses, and the script says so in its own output.

---

## What it does and does not protect

| Property | Status | Why |
|---|---|---|
| Confidentiality from the server | **Yes** | Keys never leave the endpoints |
| Message integrity and tamper detection | **Yes** | AES-256-GCM authentication tag |
| Replay and reorder resistance | **Yes** | Monotonic receive counter |
| Forward secrecy (per session) | **Yes** | Ephemeral keys, discarded after use |
| Endpoint authentication | **No** | Unauthenticated DH. See `demos/attacks.py` experiment D |
| Metadata protection | **No** | The fixed 24 byte record overhead makes plaintext length exactly recoverable. See experiment E |
| Post compromise security | **No** | No ratcheting; one key pair per session |
| Availability | **No** | The relay is a single point of failure |

---

## How it works

```
Alice                         Relay                          Bob
  |                             |                             |
  |----------- g^a mod p ------>|-----------> g^a mod p ------>|
  |<---------- g^b mod p -------|<----------- g^b mod p -------|
  |                             |                             |
  |   both sides now compute s = g^ab mod p                    |
  |   HKDF-SHA256(s) -> two keys, one per direction            |
  |                             |                             |
  |-- ctr || AES-GCM(msg) ----->|  sees only this  ----------->|
```

**Key agreement.** Ephemeral finite field Diffie-Hellman over RFC 3526 MODP Group 14
(2048 bit). Parameters are verified against the RFC generating formula in
`tests/verify_params.py` rather than trusted as a copied constant. The group is a safe
prime, so a single small subgroup check on incoming public keys is sufficient.

**Key derivation.** HKDF-SHA256 over the raw shared secret, producing two independent
256 bit keys. RFC 5869 states the extract step should not be skipped when the input is a
Diffie-Hellman value, because the output is a group element rather than uniform key
material. Two keys means the parties can never collide on a `(key, nonce)` pair.

**Record layer.** AES-256-GCM. Each record is `counter || ciphertext || tag`: an 8 byte
counter and a 16 byte tag around the ciphertext, so exactly 24 bytes of overhead. The
counter travels in clear but is passed as **associated data**, so it is covered by the tag
and cannot be rewritten. The receiver tracks the highest counter seen and rejects anything
at or below it, which blocks replay and reordering.

**All primitives** come from [`pyca/cryptography`](https://cryptography.io/). No
cryptographic mathematics is implemented by hand.

---

## Repository layout

```
src/crypto_core.py       DH, HKDF, AES-GCM session, safety numbers
src/server.py            untrusted relay; logs its own view as evidence
src/client.py            terminal chat client

web/demo_server.py       browser viewer backend (standard library only)
web/index.html           the three column page and the nine checks

demos/attacks.py         experiments A, B, B2, C, D, E
demos/nonce_reuse.py     measures the damage of a repeated nonce
demos/run_live.py        automated two client session

tests/test_crypto.py     18 tests: correctness and security properties
tests/verify_params.py   RFC 3526 parameter verification

evidence/                captured output from every run
```

---

## Troubleshooting

**`ModuleNotFoundError: No module named 'cryptography'`**
The virtual environment is not active. Run `source venv/bin/activate` from inside the
project folder, then `pip install -r requirements.txt`.

**`command not found: python3`**
Python is not installed, or is installed as `python`. Try `python --version` first.

**`Address already in use`**
Something else is using that port. Pick another: `python3 src/server.py 9010`, and start
each client with `--port 9010`. For the web page: `python3 web/demo_server.py 8100`, then
open http://127.0.0.1:8100.

**The browser did not open automatically**
Open http://127.0.0.1:8000 yourself.

**Clients connect but nothing sends**
Both clients must be running. The relay pairs them two at a time, and exactly one of them
must be started with `--initiator`.

**The RFC parameter check fails to import**
It needs `mpmath` and `sympy`, both in `requirements.txt`. Re-run
`pip install -r requirements.txt` with the virtual environment active.

---

## Ethics

Every attack in this repository was written and executed against my own software, on
loopback, on my own machine. Nothing here was pointed at a third party system. The
weaknesses are documented openly rather than concealed, because publishing something that
looks like a secure messenger while hiding that it does not authenticate endpoints would
be misleading in a way that could cause real harm.

## Licence

MIT. See `LICENSE`, which also carries a note on intended use.
