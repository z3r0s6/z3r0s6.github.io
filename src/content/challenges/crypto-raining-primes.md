---
title: "Crypto - raining primes"
date: 2026-05-10
tags: ["HackTheBox", "Crypto"]
categories: ["Machines&Challenges"]
author: "z3r0s"
---
# Raining Primes Write-up

## Summary

The service mixes three ideas:

1. Prime generation of the form `p = a*r + b`
2. A homomorphic-looking key update routine
3. RSA encryption of an AES-encrypted flag

The design breaks because the same hidden 640-bit prime `r` is reused everywhere:

- every prime returned by option `1`
- both RSA primes
- the `update_key()` routine

Once `r` is recovered, the rest of the scheme collapses:

- force the AES key to all zeroes
- factor the RSA modulus using the known `r`
- RSA-decrypt the AES ciphertext
- AES-decrypt the flag with the zero key

Recovered flag:

```text
HTB{c0mb1n1ng_4ppr0x1m4t3_GCD___l4tt1c3s___RS4___4nd___h0m0m0rph1c_3ncrypt10n___4ll_1n_0n3!}
```

## Relevant Code

From [server.py](/home/kali/chall/crypto_raining_primes/server.py):

```python
A, B, P, R = 384, 256, 1024, 640

def a() -> int: return randbits(A)
def b() -> int: return randbits(B)
```

Each generated prime has the form:

```python
if (p := a() * self.r + b()).bit_length() == P and isPrime(p):
    return p
```

So every prime is:

```text
p = a*r + b
```

with:

- `a` about 384 bits
- `r` exactly 640 bits
- `b` about 256 bits

The AES key is initially random, but `update_key()` replaces it with:

```python
k0 = self._public_key(b2v(self.key))
k = [k0_i * k1_i for k0_i, k1_i in zip(k0, k1)]
bits = [(k_i % self.r) % 2 for k_i in k]
self.key = v2b(bits)
```

And the flag is encrypted as:

1. AES-ECB under `self.key`
2. RSA with modulus `n = p*q`

## Step 1: Recover the Hidden Prime `r`

The server returns many values of the form:

```text
p_i = a_i*r + b_i
```

with small error term `b_i < 2^256`.

For two such primes:

```text
p1 / p2 = (a1*r + b1) / (a2*r + b2) ~= a1 / a2
```

because `b1` and `b2` are much smaller than `a_i*r`.

That means the rational number `a1/a2` appears as a very good approximation to `p1/p2`. The standard way to recover such approximants is to enumerate the convergents of the continued fraction of `p1/p2`.

When a convergent `(x, y)` matches `(a1, a2)`, we get:

```text
r ~= p1 / x
```

In practice:

1. Request several primes from option `1`
2. For each pair, compute convergents of `p_i / p_j`
3. Keep candidates where the convergent numerators and denominators are in the expected 384-bit range
4. Set `r = p_i // x`
5. Verify that every sampled prime satisfies `p mod r < 2^256`

That recovers the exact hidden `r`.

This is essentially an approximate-GCD style failure, with continued fractions enough for the given parameter sizes.

## Step 2: Force the AES Key to All Zeroes

The server computes:

```text
k0_i = A_i*r + m_i
```

where:

```text
m_i = 2*t_i + bit_i
```

so `m_i mod 2` equals the corresponding key bit.

Then it multiplies by attacker-controlled `k1_i` and keeps:

```text
bit'_i = ((k0_i * k1_i) mod r) mod 2
```

If we submit each `k1_i` as a multiple of `r`, for example:

```text
k1_i = 2*r
```

then:

```text
(k0_i * k1_i) mod r = 0
```

for every position, so:

```text
bit'_i = 0
```

Hence the new AES key becomes:

```text
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

That satisfies the assertion too, because the server only requires:

```text
self.r < k1_i <= 2^A * self.r
```

and `2*r` is valid.

## Step 3: Request the RSA Ciphertext

After zeroing the key, choose option `3`.

The server returns:

```text
(n, e, c)
```

where:

- `n = p*q`
- `e = 65537`
- `c = m^e mod n`
- `m` is the integer encoding of `AES_ECB_zero_key(flag)`

## Step 4: Factor `n` Using Known `r`

The RSA primes are generated in the same way:

```text
p = a_p*r + b_p
q = a_q*r + b_q
```

Expand the modulus:

```text
n = (a_p*r + b_p)(a_q*r + b_q)
  = a_p*a_q*r^2 + (a_p*b_q + a_q*b_p)r + b_p*b_q
```

Define:

```text
x = a_p*a_q
y = a_p*b_q + a_q*b_p
z = b_p*b_q
```

Then:

```text
n = x*r^2 + y*r + z
```

with:

- `z = n mod r`
- `y` obtainable from `(n - z) / r`, up to a tiny carry adjustment

More concretely:

```text
z = n mod r
qr = (n - z) / r = x*r + y
```

Because `y` can exceed `r`, there may be a small carry. Testing a few carry values is enough.

Once `x`, `y`, and `z` are known, note that:

```text
x = a_p*a_q
z = b_p*b_q
y = a_p*b_q + a_q*b_p
```

So `a_p*b_q` and `a_q*b_p` are the roots of:

```text
t^2 - y*t + x*z = 0
```

The discriminant is:

```text
Delta = y^2 - 4*x*z
```

which is a perfect square in the correct carry case. That gives:

```text
t1 = (y + sqrt(Delta)) / 2
t2 = (y - sqrt(Delta)) / 2
```

From there, recover a valid split and reconstruct:

```text
p = a_p*r + b_p
q = a_q*r + b_q
```

Finally verify:

```text
p*q == n
```

## Step 5: Decrypt RSA, Then AES

After factoring:

```text
phi = (p - 1)(q - 1)
d = e^{-1} mod phi
```

and:

```text
m = c^d mod n
```

This gives the AES ciphertext as an integer converted back to bytes.

Since the AES key was forced to all zeroes, decrypt with AES-ECB under:

```text
00 * 32
```

then PKCS#7-unpad the result to obtain the flag.

## Exploit Script

Solver used:

- [solve.py](/home/kali/chall/crypto_raining_primes/solve.py)

Run it with:

```bash
python3 solve.py
```

## Final Notes

The challenge combines several weak design choices:

- reusing the same hidden structured prime `r`
- exposing many samples of `a*r + b`
- allowing attacker-controlled multiplication before reduction modulo `r`
- deriving RSA primes from the same hidden structure

Any one of these ideas might be salvageable in a different context, but together they make the system completely breakable.
