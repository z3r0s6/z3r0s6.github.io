---
title: "Reverse Engineering - rauth"
date: 2026-05-10
tags: ["HackTheBox", "Reverse Engineering"]
categories: ["Machines&Challenges"]
difficulty: "Medium"
os: "Linux"
author: "z3r0s"
---
# HTB Reverse Challenge: rauth

## Challenge Info

- **Category:** Reverse Engineering
- **Description:** "My implementation of authentication mechanisms in C turned out to be failures. But my implementation in Rust is unbreakable. Can you retrieve my password?"
- **Flag:** `HTB{I_Kn0w_h0w_t0_5al54}`

## Analysis

The binary is a 64-bit ELF Rust executable, dynamically linked, with debug info and not stripped.

```
$ file rauth
rauth: ELF 64-bit LSB pie executable, x86-64, dynamically linked, with debug_info, not stripped
```

### Identifying the Cipher

Strings reveal the binary uses the **Salsa20** stream cipher:

```
/home/w3th4nds/.cargo/registry/src/github.com-1ecc6299db9ec823/salsa20-0.8.0/src/core.rs
/home/w3th4nds/.cargo/registry/src/github.com-1ecc6299db9ec823/cipher-0.3.0/src/stream.rs
```

Key strings from the binary:

```
Welcome to secure login portal!
Enter the password to access the system:
Successfully Authenticated
Flag:
You entered a wrong password!
```

### Reversing the Main Function

The main function (`rauth::main` at `0x6460`) follows this flow:

1. Prints the welcome banner and password prompt
2. Reads user input and trims the trailing newline
3. Initializes a Salsa20 cipher with a hardcoded key and nonce
4. Encrypts the user input using `try_apply_keystream` (XORs with Salsa20 keystream)
5. Compares the encrypted result against a hardcoded 32-byte expected value
6. If match: resets the cipher buffer position, decrypts and prints the flag
7. If no match: prints "You entered a wrong password!"

### Extracting Crypto Parameters

All parameters are embedded in the `.rodata` section:

| Parameter | Address | Value |
|---|---|---|
| Key (32 bytes) | `0x39ca0` | `ef39f4f20e76e33bd25f4db338e81b10` (ASCII) |
| Nonce (8 bytes) | inline `movabs` | `d4c270a3` (ASCII) |
| Expected ciphertext (32 bytes) | `0x39cc0` | `05055fb1a329a8d558d9f556a6cb31f324432a31c99dec72e33eb66f62ad1bf9` |
| Encrypted flag (24 bytes) | `0x39cf0` | `193978899768a08f66d39017b2e040c237193763c581e261` |

### Key Observations

- The key is loaded as two 16-byte chunks via `movaps` from `0x39ca0` and `0x39cb0`
- The nonce is loaded as an 8-byte immediate via `movabs $0x3361303732633464`
- After the password check, the cipher's `buffer_pos` is reset to 0 (`movq $0x0, 0xc8(%rsp)`), meaning the flag decryption reuses keystream bytes starting from position 0

## Solution

Since Salsa20 is a stream cipher (XOR-based), decryption is the same operation as encryption. We decrypt the expected ciphertext to recover the password:

```python
from Crypto.Cipher import Salsa20

key   = b"ef39f4f20e76e33bd25f4db338e81b10"
nonce = b"d4c270a3"

enc_password = bytes.fromhex(
    "05055fb1a329a8d558d9f556a6cb31f3"
    "24432a31c99dec72e33eb66f62ad1bf9"
)

cipher = Salsa20.new(key=key, nonce=nonce)
password = cipher.decrypt(enc_password)
print(password)
# b'TheCrucialRustEngineering@2021;)'
```

### Getting the Flag

```
$ echo "TheCrucialRustEngineering@2021;)" | nc 154.57.164.64 32005
Welcome to secure login portal!
Enter the password to access the system:
Successfully Authenticated
Flag: "HTB{I_Kn0w_h0w_t0_5al54}"
```

## Key Takeaways

- The binary uses **Salsa20** (a stream cipher) to verify the password by encrypting user input and comparing against stored ciphertext
- Since stream ciphers are XOR-based, knowing the key, nonce, and ciphertext is sufficient to recover the plaintext
- The key, nonce, and expected ciphertext are all hardcoded in the binary's `.rodata` section
- Having debug symbols and the binary not being stripped made symbol resolution straightforward
