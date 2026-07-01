---
title: "Quantum - untrusted node"
date: 2026-05-10
tags: ["HackTheBox", "Quantum"]
categories: ["Machines&Challenges"]
author: "z3r0s"
---


---


**Name -** Untrusted Node

**Category -** Quantum

**Difficulty -** Medium

**Link -** https://app.hackthebox.com/challenges/Untrusted%2520Node

### Summary

The challenge presents a Quantum Key Distribution (QKD) simulation. The "Transmitter" (Alice) sends qubits to a "Receiver" (Bob), but there is a redundancy flaw: for every bit of the key, Alice sends a "chunk" of identical qubits. We act as the compromised "Trusted Node" in the middle. By measuring the first two qubits of each chunk in different bases and letting the rest pass to Bob, we can recover the key without alerting the protocol during the reconciliation phase.

---

### Recon (how I inspected the format)

We are given 4 Python files: `receiver.py`, `server.py`, `transmitter.py`, and `util.py`.

Analyzing the code, I identified the core vulnerability in the transmission logic:
1.  **Redundancy:** Alice (`transmitter.py`) doesn't send just one qubit per bit. She sends a "chunk" of $k$ copies ($k \ge 2$). All qubits in a chunk encode the *same bit* in the *same basis*.
2.  **Interception:** We sit in the middle. We can choose to measure qubits or pass them (`-1`) to Bob.
3.  **Reconciliation Control:** After transmission, the server asks us for the list of gates to send back to the Transmitter for matching. The Transmitter iterates through the chunk and picks the *first* qubit where the provided gate matches Alice's basis.

---

### Strategy

My strategy exploits the redundancy to perform a perfect Man-in-the-Middle attack. Since we don't know Alice's basis (X or Z) ahead of time, we need to cover both possibilities using the redundant qubits.

1.  **Measurement Phase:**
    *   Since every qubit in a chunk is identical, I don't need to guess the basis.
    *   I intercept the **first two qubits** of every chunk.
    *   I measure qubit #0 in the **Z-basis** (gate `0`) to get result $R_Z$.
    *   I measure qubit #1 in the **X-basis** (gate `1`) to get result $R_X$.
    *   I let the remaining $k-2$ qubits pass to Bob (gate `-1`).
    *   *Result:* I now possess the bit value for *both* possible bases.

2.  **Reconciliation Phase:**
    *   Bob measures the passed qubits randomly. The server shows us Bob's gates.
    *   We need the Transmitter to generate the key based on *Bob's* successful measurements (so the protocol thinks everything is fine), but we need to know the value.
    *   To do this, we must force the Transmitter to **skip** our measured qubits (indices 0 and 1).
    *   I send an invalid gate ID (e.g., `2`) for the first two positions. Since the valid bases are only `0` or `1`, `2` will never match, and the Transmitter will continue checking the rest of the chunk.
    *   For the remaining positions, I copy Bob's gates.

3.  **Key Recovery:**
    *   The server returns the `matches`. If a match occurs on a qubit Bob measured, I check which basis Bob used.
    *   If Bob used Z (0), the key bit is my $R_Z$.
    *   If Bob used X (1), the key bit is my $R_X$.

---

### Failures (The Path of Pain)

This challenge was less about the crypto logic and more about fighting with Python sockets.

**Attempt 1: Standard Sockets**
I started by writing a script using the standard `socket` library. I tried to parse the output line by line using `f.readline()`.

```python
# Failed Attempt 1
import socket
import ast
import hashlib

HOST = '94.237.121.111'
PORT = 50073

def solve():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    f = s.makefile()

    # Reading sync signal
    sync_signal = []
    while True:
        line = f.readline() # Hand here
        if "Sync signal:" in line:
            sync_signal = ast.literal_eval(line.split(":")[1].strip())
            break
    
    # ... logic for payloads ...
    
    # Sending payload
    s.sendall((payload_1 + "\n").encode())
```

**Result:** Nothing. The script just hung. The server probably wasn't sending a newline character immediately, or the buffering was messing up the flow.

**Attempt 2: Manual Byte Reading**
I decided to "fix" the buffering issue by reading byte-by-byte and looking for brackets `]` to detect the end of lists, or implementing a custom `recv_until`.

```python
# Failed Attempt 2
def recv_until(sock, delimiter):
    data = b""
    while delimiter.encode() not in data:
        chunk = sock.recv(1024)
        if not chunk:
            break
        data += chunk
        print(chunk.decode(), end='', flush=True)
    return data.decode()

# ... inside solve ...
    line = ""
    while "]" not in line:
        char = s.recv(1).decode() # Reading 1 byte at a time... slow and ugly
        line += char
        print(char, end='', flush=True)
    sync_signal = ast.literal_eval(line.strip())
```

**Result:** It worked... partially.
```
[*] Connected to server...
Operator, Knox here... Sync signal: [2, 4, ... ]
Specify the gates to intercept receiver's measurement:
```
But parsing the responses was a nightmare. The stream contained text mixed with lists, and `ast.literal_eval` kept failing because of extra characters. Plus, timing issues meant I was sometimes reading partial lines.

---

### Solution (The Working Script)

I realized I was wasting time reinventing the wheel. I switched to `pwntools`, which handles `recvuntil`, buffering, and line endings perfectly.

```python
from pwn import *
import ast
import hashlib

HOST = '94.237.121.111'
PORT = 50073

def xor(a: bytes, b: bytes):
    return bytes([x ^ y for x, y in zip(a, b)])
def solve():
    r = remote(HOST, PORT)
    r.recvuntil(b"Sync signal: ")
    sync_data = r.recvline().strip().decode()
    sync_signal = ast.literal_eval(sync_data)
    log.info(f"Got Sync Signal. Total chunks: {len(sync_signal)}")
    tn_gates_measure = []
    for k in sync_signal:
        tn_gates_measure.extend([0, 1])
        if k > 2:
            tn_gates_measure.extend([-1] * (k - 2))
    payload_1 = ",".join(map(str, tn_gates_measure))
    r.sendlineafter(b"measurement: ", payload_1.encode())    
    log.info("Payload 1 sent. Waiting for quantum simulation (this may take time)...")
    r.recvuntil(b"Trusted Node results: ")
    tn_results_data = r.recvline().strip().decode()
    tn_results = ast.literal_eval(tn_results_data)  
    log.success(f"Captured TN results: {len(tn_results)}")
    chunk_intercepts = []
    res_idx = 0
    for _ in sync_signal:
        val_z = tn_results[res_idx]
        val_x = tn_results[res_idx+1]
        chunk_intercepts.append({'0': val_z, '1': val_x})
        res_idx += 2
    r.recvuntil(b"Receiver gates: ")
    rx_gates_data = r.recvline().strip().decode()
    rx_gates = ast.literal_eval(rx_gates_data)
    tn_gates_matches = []
    global_idx = 0   
    for k in sync_signal:
        tn_gates_matches.extend([2, 2]) # Garbage gates
        global_idx += 2       
        for _ in range(k-2):
            tn_gates_matches.append(rx_gates[global_idx])
            global_idx += 1          
    payload_2 = ",".join(map(str, tn_gates_matches))
    r.sendlineafter(b"intercept receiver gates : ", payload_2.encode())
    r.recvuntil(b"Transmitter matches: ")
    tx_matches_data = r.recvline().strip().decode()
    tx_matches = ast.literal_eval(tx_matches_data)
    raw_key_bits = ""
    global_idx = 0
    for chunk_idx, k in enumerate(sync_signal):
        for i in range(k):
            is_match = tx_matches[global_idx]
            if is_match:
                basis_used = rx_gates[global_idx]
                bit = chunk_intercepts[chunk_idx][str(basis_used)]
                raw_key_bits += bit          
            global_idx += 1
    log.success(f"Recovered Key Bits: {raw_key_bits}")
    final_key = hashlib.sha256(raw_key_bits.encode()).digest()
    command = "TX|FETCH|SECRET"
    encrypted_cmd = xor(command.encode(), final_key).hex()   
    r.sendlineafter(b"to receiver : ", encrypted_cmd.encode())
    r.interactive()
    flag = r.recvall().decode().strip()
    flag = r.recvall().decode().strip()   
    print("\n" + "="*30)
    print(f"FLAG: {flag}")
    print("="*30)
if __name__ == "__main__":
    solve()
```

---

### Result and proofs

Running the `pwntools` script successfully intercepted the key and retrieved the flag:

```
â”Œâ”€â”€(vt729830ã‰¿vt72983)-[~/htb]
â””â”€$ python3 1.py
[+] Opening connection to 94.237.121.111 on port 50073: Done
[*] Got Sync Signal. Total chunks: 128
[*] Payload 1 sent. Waiting for quantum simulation (this may take time)...
[+] Captured TN results: 256
[+] Recovered Key Bits: 11010101000001110011110110010101001010011011010000110000111110111111111111001
[*] Switching to interactive mode
Command: HTB{******_******_*********_******_**_****_***********_*******_************!}
Specify the data to send to receiver : $
```

So we got the flag easier than in Phase Madness XD.

By the way, the redesign is worse than it used to be :(

