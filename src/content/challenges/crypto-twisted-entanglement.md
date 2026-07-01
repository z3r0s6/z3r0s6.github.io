---
title: "Crypto - twisted entanglement"
date: 2026-05-10
tags: ["HackTheBox", "Crypto"]
categories: ["Machines&Challenges"]
author: "z3r0s"
---
# Twisted Entanglement Write-Up

## Target

- Host: `154.57.164.77:30486`
- Flag: `HTB{Ek3rT_W4s_s000_b0R1nG_1N_1991_4nD_1_h4t3_Pr0b4b1l1Ty_s0_I_Us3_4_ECC_S33d!}`

## Vulnerabilities

The challenge has two independent weaknesses that chain together cleanly.

### 1. Invalid-curve scalar multiplication

Menu option `1` accepts an arbitrary user point and computes:

```python
public_key = multiply(private_key, point, E)
```

There is no validation that the input point lies on the original secp256k1 curve. The code only uses `a` and `p` inside the EC formulas, so any point on any curve of the form:

```text
y^2 = x^3 + b    over F_p
```

with the same `a = 0` and the same field prime `p` will still be processed.

That makes invalid-curve small-subgroup attacks possible. If we send a point of known order `r`, the server returns `[d]P`, and we can recover `d mod r`.

### 2. Predictable quantum basis sequence

Menu option `2` calls:

```python
seed(private_key)
```

and then generates the server basis with Python's `random.randint`. Once the EC private key is known, the 256 basis choices are fully reproducible.

The simulated qubits are prepared in the Bell singlet state, so when both sides measure with the same basis, the bits are always opposite. If we submit the exact same basis string the server will use, then:

```text
q_server_bit = 1 - q_user_bit
```

for every position.

The server hashes the 256 server bits with SHA-256 and uses that digest as the AES key, so inverting the returned `q_user_key` bitstream is enough to recover the key and decrypt the ciphertext.

## Exploit Strategy

I used three fixed base points and only three menu-`1` queries total.

### Query 1: `b = 6` invalid curve

This point came from the public write-up you linked and has a known subgroup order:

```text
P1 = (
  97739641136662608657079256755827419133838433889311376347497047878595450848685,
  98100600220769146147883276184268394981687000350669426476581029710371895499142
)

ord(P1) =
8270863516951156815969356072049136275281522608437447405948333614614684278506
```

I projected `[d]P1` into the prime-order subgroups:

```text
2, 7, 10903, 5290657
```

and solved the tiny discrete logs locally with baby-step/giant-step.

### Query 2: another twist class

I used:

```text
P2 = (
  49635389726789206144354041527609049426118189034847538710664007433041802716694,
  37162158397973984254862982683298013147773194106535989248340413239503178429945
)
```

and recovered:

```text
13, 3319, 22639
```

### Query 3: another twist class

I used:

```text
P3 = (
  49729834587555216348787698505432362834671204906164643189001602709865068726320,
  56036100942499123875868836528371921255792746260155713647618806678334179859355
)
```

and recovered:

```text
199, 18979
```

The product of all recovered prime moduli is larger than the server's bound:

```text
private_key < 8748541127929402731638
```

so CRT gives the exact private key:

```text
d = 3262827136301000405966
```

## Final Decryption

From `d`, reproduce the server basis:

```python
random.seed(d)
basis = "".join("Z" if random.randint(0, 1) else "X" for _ in range(256))
```

Submit that basis to menu `2`, parse the returned `q_user_key`, flip every bit, hash the 32 reconstructed bytes with SHA-256, and decrypt the AES-ECB ciphertext.

That yields:

```text
HTB{Ek3rT_W4s_s000_b0R1nG_1N_1991_4nD_1_h4t3_Pr0b4b1l1Ty_s0_I_Us3_4_ECC_S33d!}
```

## Solver

The final solver is in:

- [solve.py](/home/kali/chall/twisted_entanglement/solve.py)

```python
#!/usr/bin/env python3
import ast
import hashlib
import math
import random
import re
import socket
from dataclasses import dataclass

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


HOST = "154.57.164.77"
PORT = 30486

P = 115792089237316195423570985008687907853269984665640564039457584007908834671663
BOUND = 8748541127929402731638
O = None

# secp256k1 has j = 0. For p = secp256k1's field prime we have 4p = u^2 + 27v^2,
# and the six sextic-twist traces follow from that CM relation.
U = 432420386565659656852420866390673177327
V = 101138146489082181198416925222535253057
TRACES = [
    U,
    (-U + 9 * V) // 2,
    (-U - 9 * V) // 2,
    -U,
    (U - 9 * V) // 2,
    (U + 9 * V) // 2,
]
ORDERS = [P + 1 - t for t in TRACES]

# One query per base point is enough. We project the returned image into small
# prime-order subgroups locally and recover d modulo each prime with BSGS.
BASE_POINTS = [
    {
        "name": "b=6 invalid curve",
        "point": (
            97739641136662608657079256755827419133838433889311376347497047878595450848685,
            98100600220769146147883276184268394981687000350669426476581029710371895499142,
        ),
        "order": 8270863516951156815969356072049136275281522608437447405948333614614684278506,
        "factors": [2, 7, 10903, 5290657],
    },
    {
        "name": "twist class 3",
        "point": (
            49635389726789206144354041527609049426118189034847538710664007433041802716694,
            37162158397973984254862982683298013147773194106535989248340413239503178429945,
        ),
        "order": ORDERS[3],
        "factors": [13, 3319, 22639],
    },
    {
        "name": "twist class 4",
        "point": (
            49729834587555216348787698505432362834671204906164643189001602709865068726320,
            56036100942499123875868836528371921255792746260155713647618806678334179859355,
        ),
        "order": ORDERS[4],
        "factors": [199, 18979],
    },
]


def inv(x: int) -> int:
    return pow(x % P, -1, P)


def neg(pt):
    if pt is O:
        return O
    x, y = pt
    return (x, (-y) % P)


def add(pt1, pt2):
    if pt1 is O:
        return pt2
    if pt2 is O:
        return pt1

    x1, y1 = pt1
    x2, y2 = pt2

    if x1 == x2 and (y1 + y2) % P == 0:
        return O

    if pt1 == pt2:
        s = (3 * x1 * x1) * inv(2 * y1)
    else:
        s = (y2 - y1) * inv(x2 - x1)

    s %= P
    x3 = (s * s - x1 - x2) % P
    y3 = (s * (x1 - x3) - y1) % P
    return (x3, y3)


def mul(k: int, pt):
    res = O
    cur = pt
    while k:
        if k & 1:
            res = add(res, cur)
        cur = add(cur, cur)
        k >>= 1
    return res


def discrete_log_bsgs(base, target, order: int) -> int:
    m = math.isqrt(order) + 1
    table = {}
    cur = O
    for j in range(m):
        table.setdefault(cur, j)
        cur = add(cur, base)

    step = neg(mul(m, base))
    gamma = target
    for i in range(m + 1):
        j = table.get(gamma)
        if j is not None:
            x = i * m + j
            if x < order:
                return x
        gamma = add(gamma, step)

    raise ValueError("discrete log not found")


def crt_pair(a1, m1, a2, m2):
    g = math.gcd(m1, m2)
    if (a2 - a1) % g != 0:
        raise ValueError("inconsistent congruences")
    lcm = m1 // g * m2
    if m1 == 1:
        return a2 % m2, m2
    if m2 == 1:
        return a1 % m1, m1
    k = ((a2 - a1) // g) * pow(m1 // g, -1, m2 // g)
    return (a1 + m1 * k) % lcm, lcm


@dataclass
class Remote:
    host: str
    port: int

    def __post_init__(self):
        self.sock = socket.create_connection((self.host, self.port))
        self.buf = b""
        self._recv_until(b"Public Key: ")
        self.public_key = ast.literal_eval(self._recv_line().decode().strip())

    def _recv_until(self, marker: bytes) -> bytes:
        while marker not in self.buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise EOFError("connection closed")
            self.buf += chunk
        idx = self.buf.index(marker) + len(marker)
        out = self.buf[:idx]
        self.buf = self.buf[idx:]
        return out

    def _recv_line(self) -> bytes:
        return self._recv_until(b"\n")[:-1]

    def _recv_nonempty_line(self) -> str:
        while True:
            line = self._recv_line().decode()
            if line.strip():
                return line

    def _send_line(self, text: str):
        self.sock.sendall(text.encode() + b"\n")

    def _menu_prompt(self):
        self._recv_until(b"\n> ")

    def query_point(self, pt):
        self._menu_prompt()
        self._send_line("1")
        self._recv_until(b"Enter your point x,y: ")
        self._send_line(f"{pt[0]},{pt[1]}")
        line = self._recv_nonempty_line()
        match = re.search(r"Here's your new Public Key: (.+)", line)
        if not match:
            raise ValueError(f"unexpected response: {line!r}")
        return tuple(ast.literal_eval(match.group(1)))

    def quantum(self, basis: str):
        self._menu_prompt()
        self._send_line("2")
        self._recv_until(b"Choose your 256 basis for the KEP: ")
        self._send_line(basis)
        q_line = self._recv_nonempty_line()
        c_line = self._recv_nonempty_line()
        q_match = re.search(r"The Quantum key: ([0-9a-f]+)", q_line)
        c_match = re.search(r"Flag Encrypted: ([0-9a-f]+)", c_line)
        if not q_match or not c_match:
            raise ValueError(f"unexpected quantum response: {q_line!r} / {c_line!r}")
        return q_match.group(1), bytes.fromhex(c_match.group(1))


def recover_private_key(remote: Remote):
    residue = 0
    modulus = 1

    for base in BASE_POINTS:
        pt = base["point"]
        order = base["order"]
        image = remote.query_point(pt)
        print(f"[+] queried {base['name']}", flush=True)

        for prime in base["factors"]:
            sub_base = mul(order // prime, pt)
            sub_image = mul(order // prime, image)
            d_mod_prime = discrete_log_bsgs(sub_base, sub_image, prime)
            residue, modulus = crt_pair(residue, modulus, d_mod_prime, prime)
            print(f"[+] d mod {prime} = {d_mod_prime}", flush=True)
            print(f"[+] combined modulus bits = {modulus.bit_length()}", flush=True)

    if modulus <= BOUND:
        raise ValueError("CRT modulus did not exceed the private-key bound")

    return residue


def server_basis_from_private_key(private_key: int) -> str:
    random.seed(private_key)
    return "".join("Z" if random.randint(0, 1) else "X" for _ in range(256))


def invert_bitstring_from_hex(data_hex: str) -> bytes:
    bits = bin(int(data_hex, 16))[2:].zfill(len(data_hex) * 4)
    flipped = "".join("1" if b == "0" else "0" for b in bits)
    return bytes(int(flipped[i:i + 8], 2) for i in range(0, len(flipped), 8))


def decrypt_flag(ciphertext: bytes, q_user_hex: str) -> bytes:
    q_server_bytes = invert_bitstring_from_hex(q_user_hex)
    key = hashlib.sha256(q_server_bytes).digest()
    return unpad(AES.new(key, AES.MODE_ECB).decrypt(ciphertext), 16)


def main():
    modulus = math.prod(prime for base in BASE_POINTS for prime in base["factors"])
    if modulus <= BOUND:
        raise ValueError("selected subgroups are insufficient")

    remote = Remote(HOST, PORT)
    print(f"[+] remote public key: {remote.public_key}", flush=True)

    private_key = recover_private_key(remote)
    print(f"[+] recovered private key = {private_key}", flush=True)
    if not (0 <= private_key < BOUND):
        raise ValueError("recovered key is outside the asserted bound")

    basis = server_basis_from_private_key(private_key)
    q_user_hex, ciphertext = remote.quantum(basis)
    flag = decrypt_flag(ciphertext, q_user_hex).decode()

    print(f"[+] basis = {basis}", flush=True)
    print(f"[+] q_user_key = {q_user_hex}", flush=True)
    print(f"[+] ciphertext = {ciphertext.hex()}", flush=True)
    print(f"[+] flag = {flag}", flush=True)


if __name__ == "__main__":
    main()

```


Run it with:

```bash
python3 -u solve.py
```
