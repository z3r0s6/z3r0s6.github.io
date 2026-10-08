---
title: "Quantum - flagportation"
date: 2026-05-10
tags: ["HackTheBox", "Quantum"]
categories: ["Machines&Challenges"]
author: "z3r0s"
---
# HTB Write-up: Flagportation

Link - https://app.hackthebox.com/challenges/Flagportation



---


**Category:** Quantum
**Difficulty:** Very Easy

### Summary

The server implements a simplified quantum teleportation protocol: it encodes bit pairs (`00`, `01`, `10`, `11`) into a 3-qubit state, measures the first two qubits and prints the measurement results and the basis (`Z` or `X`) used to encode the original bits. Your job is to send instructions (which gates to apply to the third qubit) and choose the measurement basis for the third qubit. From the returned measurement you can reconstruct the original two-bit pair.

The solution is mainly automating the interaction and applying the teleportation corrections: you should apply the operator (X^{m_1} Z^{m_0}) to the receiver qubit (where (m_0) is the measurement of qubit 0 and (m_1) is the measurement of qubit 1). The server doesn't accept an empty instruction string, so for the no-correction case we use a no-op trick (for example, `Z:2;Z:2`, which results in the identity).

---

### Recon (how I inspected the format)

I used `nc`/`netcat` to connect and inspected the server output. Example output:

```
â”Œâ”€â”€(vt729830ã‰¿vt72983)-[~/999]
â””â”€$ nc 94.237.51.21 49721

        â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
        â•‘    Qubitrix's Teleporter    â•‘
        â•‘       Terminal (QTT)        â•‘
        â• â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•£
        â•‘ Every 24 hours, Qubitrix    â•‘
        â•‘ will release a secret       â•‘
        â•‘ message to our partners.    â•‘
        â•‘ Please follow the           â•‘
        â•‘ instructions we sent you    â•‘
        â•‘ by email from               â•‘
        â•‘ info@qubitrix.com.          â•‘
        â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

Qubit 1/204
Basis : Z
Measurement of qubit 0 : 1
Measurement of qubit 1 : 1
Specify the instructions :
Invalid instruction: . Expected format: <gate>:<params>
Examples: H:<target> | RX:<phase>,<target>
Closing QTT...
```

Make a screenshot of your `nc` session and include it in the repository (example: `Flagportation/image.png`).

![nc output](/images/quantum-flagportation/image.png)

---

### Strategy

1. Split the flag into 2-bit chunks. The server already does that on its side, we need to reconstruct the same pairs from the messages.
2. For each round the server gives the `basis` (Z or X) and measurement outcomes `m0` and `m1`.
3. Send instructions that implement the correction operator (X^{m_1} Z^{m_0}) on qubit 2. Because the server applies gates sequentially as `state = gate * state`, sending `Z:2` then `X:2` results in the operator `X * Z`, which matches the correction for `m0=1,m1=1`.
4. Send the same basis (`Z` or `X`) for the measurement of qubit 2 and read the result. The recovered pair is `(first_bit, second_bit)` where `first_bit = 0` for `Z`, `1` for `X`, and `second_bit` is the measurement result of qubit 2.
5. Concatenate pairs, convert to bytes and you get the flag.

---

### Script evolution (how I iterated and fixed bugs)

**2.py â€” first attempt**

* Initial `pwntools` client. Problems:

  * fragile parsing (`recvuntil`/`recvline` brittle ordering),
  * possible wrong gate order in some branches.

**3.py â€” added reconstruction**

* Collect `reconstructed_bit_pairs` and parse the final measurement. Convert binary string to bytes:

```py
binary_string = ''.join(reconstructed_bit_pairs)
n = int(binary_string, 2)
flag_bytes = n.to_bytes((n.bit_length() + 7) // 8, 'big')
flag = flag_bytes.decode()
```

**4.py â€” final, robust version**

* Improved parsing (use `recvuntil(b"Basis : ")` and robust `recvline` parsing), ensured corrections follow (X^{m_1}Z^{m_0}) with correct ordering, and safe decoding.

Final correction logic used:

* `m0=0, m1=0` â†’ `Z:2;Z:2` (identity)
* `m0=1, m1=0` â†’ `Z:2`
* `m0=0, m1=1` â†’ `X:2`
* `m0=1, m1=1` â†’ `Z:2;X:2`

---

### Final script (short)

```py
from pwn import *

HOST = "1.1.1.1"
PORT = 0000

conn = remote(HOST, PORT)
reconstructed_bit_pairs = []

def recv_line_stripped():
    return conn.recvline().decode(errors='ignore').strip()

try:
    while True:
        conn.recvuntil(b"Basis : ")
        basis = recv_line_stripped()

        m0_line = recv_line_stripped()
        m1_line = recv_line_stripped()
        m0 = int(m0_line.split()[-1])
        m1 = int(m1_line.split()[-1])

        if m0 == 0 and m1 == 0:
            instructions = "Z:2;Z:2"
        elif m0 == 1 and m1 == 0:
            instructions = "Z:2"
        elif m0 == 0 and m1 == 1:
            instructions = "X:2"
        elif m0 == 1 and m1 == 1:
            instructions = "Z:2;X:2"
        else:
            instructions = "Z:2;Z:2"

        conn.sendlineafter(b"Specify the instructions : ", instructions.encode())
        conn.sendlineafter(b"Specify the measurement basis : ", basis.encode())

        res_line = recv_line_stripped()
        final_measurement = int(res_line.split()[-1])

        first_bit = '0' if basis == 'Z' else '1'
        reconstructed_bit_pairs.append(first_bit + str(final_measurement))

except EOFError:
    binary_string = ''.join(reconstructed_bit_pairs)
    if binary_string:
        n = int(binary_string, 2)
        flag_bytes = n.to_bytes((n.bit_length() + 7) // 8, 'big')
        try:
            flag = flag_bytes.decode()
        except:
            flag = flag_bytes
        print('FLAG:', flag)
finally:
    conn.close()
```

---

