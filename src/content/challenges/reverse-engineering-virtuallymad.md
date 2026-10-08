---
title: "Reverse Engineering - VirtuallyMad"
date: 2026-05-10
tags: ["HackTheBox", "Reverse Engineering"]
categories: ["Machines&Challenges"]
difficulty: "Medium"
os: "Linux"
author: "z3r0s"
---
# VirtuallyMad - HTB Reverse Engineering Challenge

## Flag

`HTB{0210010002100100031100010112110004130000}`

## Overview

The challenge provides a stripped ELF binary (`virtually.mad`) that implements a custom virtual machine. The user must supply a hex-encoded "code" string that, when executed by the VM, produces a specific register state.

## VM Architecture

### Registers & State

The VM allocates a 0x38-byte structure:

| Offset | Field |
|--------|-------|
| 0x00   | Register **a** (32-bit) |
| 0x04   | Register **b** (32-bit) |
| 0x08   | Register **c** (32-bit) |
| 0x0c   | Register **d** (32-bit) |
| 0x10   | Pointer to a |
| 0x18   | Pointer to b |
| 0x20   | Pointer to c |
| 0x28   | Pointer to d |
| 0x30   | **flags** (32-bit) |

All registers and flags are initialized to 0.

### Instruction Set

Instructions are dispatched by the top byte (bits 31-24) of the opcode:

| Top Byte | Operation | Description |
|----------|-----------|-------------|
| 0x01     | MOV       | `reg[dst] = value` |
| 0x02     | ADD       | `reg[dst] += value` |
| 0x03     | SUB       | `reg[dst] -= value` |
| 0x04     | CMP       | Compare value with reg[dst], set flags |
| 0x05     | EXIT      | `exit(reg[a])` |

### Opcode Encoding (32-bit)

```
Bits 31-24: Operation (top byte)
Bits 23-20: Sub-type (must be 1 for arithmetic/mov/cmp)
Bits 19-16: Destination register index (0=a, 1=b, 2=c, 3=d)
Bits 15-12: Source type (0=immediate, 1=register)
Bits 11-0:  Immediate value, or bits 11-8 = source register index
```

### CMP & Flags

The CMP handler compares the source value against the destination register:
- **Equal**: `flags |= 0x10000000` (sets the equal flag)
- **Not equal**: `flags |= 0x10000000; flags ^= 0x10000000` (clears the equal flag)

## Input Format

- The input is a hex string whose length must be divisible by 8.
- Each 8-character chunk is parsed as a 32-bit hex opcode via `strtol(..., 16)`.
- The lower 12 bits of each opcode must be `<= 0x100`, or the opcode is skipped.

## Success Conditions

After executing all opcodes, the program checks:

| Register | Required Value |
|----------|---------------|
| a        | 0x200         |
| b        | 0xFFFFFFFF    |
| c        | 0xFFFFFFFF    |
| d        | 0x00000000    |
| flags    | 0x10000000    |

Additionally, exactly **5 opcodes** must be provided.

## Per-Opcode Constraints (from main's switch)

The main loop validates each opcode by its position (index 0-4):

| Index | Required bits 27-24 | Required bits 23-16 | Extra constraint |
|-------|---------------------|---------------------|------------------|
| 0     | 0x2 (ADD)           | 0x10 (dst=a)        | lower 12 bits <= 0x100 |
| 1     | 0x2 (ADD)           | free                 | lower 12 bits == 0x100 |
| 2     | 0x3 (SUB)           | 0x11 (dst=b)        | lower 12 bits <= 0x100 |
| 3     | 0x1 (MOV)           | 0x12 (dst=c)        | lower 12 bits <= 0x100 |
| 4     | 0x4 (CMP)           | 0x13 (dst=d)        | lower 12 bits <= 0x100 |

## Solution

Working backwards from the required final state:

### Opcode 0: `02100100` -- ADD a, 0x100

- ADD (0x02), subtype=1, dst=a(0), src_type=immediate(0), value=0x100
- Effect: `a = 0 + 0x100 = 0x100`

### Opcode 1: `02100100` -- ADD a, 0x100

- Same instruction again. Satisfies constraint `(opcode & 0xFFF) == 0x100`.
- Effect: `a = 0x100 + 0x100 = 0x200`

### Opcode 2: `03110001` -- SUB b, 1

- SUB (0x03), subtype=1, dst=b(1), src_type=immediate(0), value=1
- Effect: `b = 0 - 1 = 0xFFFFFFFF`

### Opcode 3: `01121100` -- MOV c, reg[b]

- MOV (0x01), subtype=1, dst=c(2), src_type=register(1), src_reg=b(1)
- The lower 12 bits are 0x100, where bits 11-8 = 1 selects register b.
- Effect: `c = b = 0xFFFFFFFF`

### Opcode 4: `04130000` -- CMP d, 0

- CMP (0x04), subtype=1, dst=d(3), src_type=immediate(0), value=0
- Compares 0 == d(0) -> equal -> flags = 0x10000000

### Final State

```
a:     0x200       == 0x200       OK
b:     0xffffffff  == 0xffffffff  OK
c:     0xffffffff  == 0xffffffff  OK
d:     0x0         == 0x0         OK
flags: 0x10000000  == 0x10000000  OK
```

### Execution

```
$ echo "0210010002100100031100010112110004130000" | ./virtually.mad
Give me code to execute: Executing 5 opcodes.
=====
a: 0x200
b: 0xffffffff
c: 0xffffffff
d: 0x0
flags: 0x10000000
=====
This is the right answer! Validate the challenge with HTB{0210010002100100031100010112110004130000}
```
