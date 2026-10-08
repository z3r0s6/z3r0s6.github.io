---
title: "Reverse Engineering - vvm"
date: 2026-05-10
tags: ["HackTheBox", "Reverse Engineering"]
categories: ["Machines&Challenges"]
difficulty: "Medium"
os: "Linux"
author: "z3r0s"
---
# rev_vvm Writeup

## Flag

`HTB{v1rTu4L_p4sSw0rD_t3ChN0loGy}`

## Summary

The binary is a stripped PIE ELF that implements a small VM. The visible flow is:

1. Print the banner.
2. Build a dispatch table for VM opcodes by XOR-decoding multiple handler stubs from `.data`.
3. Execute a dword-based bytecode program stored in `.data` at `0x5540`.

Running the binary directly is not useful because one VM opcode calls `ptrace` and exits under tracing/debugged environments. The solve is easier statically by reconstructing the VM handlers and emulating the bytecode.

## VM Structure

The main interpreter loop is at `0x2870`.

- Current opcode stream starts at `0x5540`.
- Opcode `0x1c` is halt.
- The handler table is allocated in `fcn.00001530`.
- Several handlers are direct functions:
  - `op 3`: read input with `getline`
  - `op 7`: anti-debug via `ptrace`
  - `op 10`: print string
  - `op 15`: build a string from stack bytes

Most other handlers are XOR-decoded x86 stubs from `.data`.

## Important Semantics

The key points needed for the solve:

- `op 0` computes `strlen`, not `strlen+1`.
- `op 3` consumes one immediate dword, but it is only the initial buffer size for `getline`.
- `op 17` is a VM subroutine call.
- `op 18` reads a byte from the input string at a fixed index.

## Length Check

After printing the prompt and reading input, the VM evaluates:

```text
(((strlen(input) * 6 - 12 + 4) / 2) * 8 + 24) / 10 == 76
```

That simplifies to:

```text
(24 * strlen(input) + 16) / 10 == 76
```

So the required input length is exactly:

```text
strlen(input) = 32
```

## Main Validation

The success path starts at bytecode index `303`. It extracts the first 32 bytes of the input in a fixed permutation and packs them into eight 32-bit little-endian words:

```text
(29, 1, 0, 17)
(25, 5, 10, 31)
(3, 30, 21, 22)
(28, 16, 23, 8)
(19, 13, 20, 26)
(6, 9, 2, 18)
(11, 7, 12, 4)
(24, 14, 27, 15)
```

Those words are then rotated left by fixed amounts:

```text
15, 19, 7, 18, 12, 20, 14, 7
```

and compared against these constants:

```text
0x2a239824
0x8a73ea61
0xba3cbd99
0xddbdd50d
0xf3444305
0x47272423
0x1517dd9c
0xb639b429
```

So the solve is just:

1. Invert each rotate with `ror32`.
2. Unpack the resulting dwords as little-endian bytes.
3. Place the bytes back into the original positions.

That reconstructs the input:

```text
HTB{v1rTu4L_p4sSw0rD_t3ChN0loGy}
```

## Verification

Re-emulating the VM with:

```text
HTB{v1rTu4L_p4sSw0rD_t3ChN0loGy}
```

produces:

```text
What is the password:
Correct!
```

Since this challenge uses the password itself as the flag, the final answer is:

`HTB{v1rTu4L_p4sSw0rD_t3ChN0loGy}`
