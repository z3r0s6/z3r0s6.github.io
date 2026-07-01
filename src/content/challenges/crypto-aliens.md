---
title: "Crypto - aliens"
date: 2026-05-10
tags: ["HackTheBox", "Crypto"]
categories: ["Machines&Challenges"]
author: "z3r0s"
---

# Crypto Aliens Write-up

## Challenge Summary

We are given a remote service and a local copy of the challenge logic in `server.py`.

The service asks for a message, applies a custom padding routine, appends a similarly padded flag, and then encrypts the result with AES-ECB.

At first glance this looks annoying rather than breakable, because:

- AES uses a fresh random key on every request.
- The flag is never returned directly.
- The server appends our controlled data and the secret together before encryption.

Normally, the random-per-request key would kill the usual ECB byte-at-a-time attack, because ciphertext from one request cannot be compared against ciphertext from another request. The key observation here is that we do not need cross-request equality. We only need **same-request block equality**, and the implementation gives us exactly enough structure to force that.

## Source Review

The challenge logic is small enough to understand directly from `server.py`:

```python
class AAES():
    def __init__(self):
        self.padding = "CryptoHackTheBox"

    def pad(self, plaintext):
        return plaintext + self.padding[:(-len(plaintext) % 16)] + self.padding

    def encrypt(self, plaintext):
        cipher = AES.new(os.urandom(16), AES.MODE_ECB)
        return cipher.encrypt(pad(plaintext, 16))
```

And in `main()`:

```python
plaintext = aaes.pad(message) + aaes.pad(FLAG)
print(aaes.encrypt(plaintext.encode()).hex())
```

That gives us two important behaviors:

1. The user input is padded with a custom string, not PKCS#7.
2. The flag is padded separately and then appended.
3. The final string is UTF-8 encoded only after the custom padding is constructed.
4. AES-ECB is used.
5. A random AES key is generated per encryption request.

## First Vulnerability: ECB Still Leaks Equality

ECB encrypts identical plaintext blocks into identical ciphertext blocks under the same key.

Because the key changes every request, we cannot compare blocks across requests. But within a single ciphertext, every block was encrypted under the same key. That means if we can make:

- one block contain a guessed byte sequence we control, and
- another block contain the real secret sequence we are trying to recover,

then a block match inside that one ciphertext confirms the guess.

So the random key is a speed bump, not a full defense.

## Second Vulnerability: Character Padding vs Byte Encryption

This is the real bug that makes the challenge solvable.

The custom padding uses `len(plaintext)`, where `plaintext` is a Python string. That means the length is measured in **characters**, not bytes.

Later, the whole combined string is encoded with:

```python
plaintext.encode()
```

UTF-8 is variable width:

- ASCII characters use 1 byte
- `Ã©` uses 2 bytes
- `â‚¬` uses 3 bytes
- many emoji use 4 bytes

So if we send multibyte characters, the custom pad aligns the string to a 16-character boundary, but AES actually sees a different byte length after UTF-8 encoding.

That mismatch lets us shift where the flag lands in AES blocks without changing the serverâ€™s character-based pad logic.

This is the entire exploit primitive.

## Understanding the Layout

For an input `message`, the server encrypts:

```text
aaes.pad(message) + aaes.pad(FLAG)
```

The custom pad is:

```text
message + prefix_of("CryptoHackTheBox") + "CryptoHackTheBox"
```

So the beginning of the flag is always preceded by a known constant suffix:

```text
... CryptoHackTheBox || FLAG[0]
```

That is useful because recovering the first flag byte becomes just another â€œrecover the next byte given the previous 15 known bytesâ€ problem. For byte 0, the previous known bytes are taken from the end of `CryptoHackTheBox`.

## Why a Normal Byte-at-a-Time Attack Fails

If the key were fixed, we could recover the flag with the standard method:

1. Shift the unknown byte to the end of a block.
2. Build a dictionary of candidate blocks.
3. Compare the target block against the dictionary.

Here that fails if done naively, because the dictionary request and the target request would use different AES keys.

So we need a way to place:

- the target block, and
- every candidate dictionary block,

inside the **same encryption request**.

That is the central idea of the solve.

## Building an In-Request Dictionary

Suppose we already know some prefix of the flag. To recover the next byte, we want a 16-byte block of the form:

```text
known_last_15_bytes || candidate
```

for every possible printable candidate.

We can inject those candidate blocks directly into our input. If all of those blocks appear in the same plaintext as the real target block from the flag region, then the correct guess is the one whose ciphertext block matches the target block.

That gives us a same-request dictionary attack.

## The Alignment Problem

There is still one catch: our input goes through `aaes.pad(message)` before the flag is appended.

So the plaintext before the flag is:

```text
message
+ custom_fill_to_16_char_boundary
+ "CryptoHackTheBox"
```

That extra custom padding changes where the flag begins. If we want the next unknown flag byte to appear at the end of an AES block, we need to control the byte length of everything that comes before it.

The bug gives us exactly that control.

## Using Multibyte Characters as a Byte Shifter

Let `Ã©` be our shifter character. It counts as:

- 1 character to Pythonâ€™s `len()`
- 2 bytes after UTF-8 encoding

If we place `u` copies of `Ã©` at the start of the message, the server thinks it added `u` characters, but AES sees `2u` bytes.

That means the byte alignment and the character alignment drift apart by `u` bytes.

We then add enough ASCII filler so that the dictionary blocks start cleanly on AES block boundaries. This lets us do two things at once:

1. Position the real flag byte we want at the end of a target block.
2. Keep our injected dictionary blocks perfectly aligned as separate 16-byte blocks.

## Recovering Each Byte

For byte index `i` of the flag:

1. Compute how many shifter characters are needed so that `FLAG[i]` lands at the end of an AES block.
2. Add ASCII filler so that the dictionary region starts exactly on a block boundary.
3. Build a dictionary consisting of every block:

```text
context || candidate
```

where `context` is the last 15 known bytes before `FLAG[i]`.

4. Send one request containing:

```text
multibyte_shim + ascii_alignment + dictionary_blocks
```

5. Split the ciphertext into 16-byte blocks.
6. Identify which block corresponds to the real target block in the flag area.
7. Compare that target block to all dictionary blocks in the same ciphertext.
8. The matching block reveals the correct next character.

Then repeat until `}` is recovered.

## Where the 15 Known Bytes Come From

For the first unknown flag byte, we do not know any flag bytes yet. But the bytes immediately before the flag are known:

```text
CryptoHackTheBox
```

So for byte 0, the 15-byte context is:

```text
ryptoHackTheBox
```

For later bytes, the context becomes the last bytes of:

```text
CryptoHackTheBox + recovered_flag_prefix
```

That is exactly what the solver does.

## Solver Walkthrough

The exploit script is in `solve.py`.

### Oracle

`oracle()` opens a connection, waits for the prompt, sends a UTF-8 string, and returns the ciphertext bytes.

### Dictionary Construction

For each flag byte index:

- `delta = (15 - i) % 16` decides how many multibyte characters are needed.
- `SHIM * delta` contributes `2 * delta` bytes while only counting as `delta` characters to the serverâ€™s custom pad.
- `"A" * ((-2 * delta) % 16)` repairs block alignment so the dictionary region begins on a 16-byte boundary.

The dictionary is built from:

```python
context = (PAD + recovered)[-15:]
dictionary = "".join((context + ch.encode()).decode("ascii") for ch in ALPHABET)
```

Each candidate contributes one full 16-byte block.

### Locating the Target Block

The target block lives inside the separately padded `FLAG` section, not inside our injected dictionary region. The script computes the exact prefix length in bytes before the flag:

```python
char_pad = (-len(message)) % 16
prefix_len = len(message.encode("utf-8")) + char_pad + len(PAD)
target_idx = (prefix_len + i) // 16
```

That `target_idx` is the ciphertext block containing the next unknown flag byte.

### Matching

Once the ciphertext is split into blocks, the script searches the dictionary region for a block equal to `blocks[target_idx]`.

The matching candidate is the recovered next character.

## Why This Works Reliably

The exploit depends only on deterministic ECB behavior inside one encryption call:

- same plaintext block
- same AES key
- same ciphertext block

It does not require:

- key reuse across requests
- decryption capability
- a padding oracle
- timing differences

The attack is entirely structural.

## Recovered Flag

Running the solver against the remote host recovered:

```text
HTB{d6a0e07e3660234bfef5cc06dd29da2105e65a8b6a13eb299e52f99dd9a3d9ab}
```

## Final Notes

This is a nice challenge because the obvious â€œECB oracleâ€ idea appears blocked by the random key, but the Unicode length mistake quietly reintroduces enough control to recreate a byte-at-a-time attack inside a single request.

In practice, this kind of bug comes from mixing:

- string-level logic
- byte-level crypto
- custom padding

That combination is fragile. The safe pattern is:

1. work in bytes, not Unicode strings
2. do not invent custom padding unless absolutely necessary
3. never use ECB for secret-dependent structured plaintext

## Files

- Challenge logic: `server.py`
- Solver: `solve.py`
