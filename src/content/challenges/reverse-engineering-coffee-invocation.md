---
title: "Reverse Engineering - Coffee Invocation"
date: 2026-05-10
tags: ["HackTheBox", "Reverse Engineering"]
categories: ["Machines&Challenges"]
difficulty: "Medium"
os: "Linux"
author: "z3r0s"
---
# Coffee Invocation Writeup

## Flag

`HTB{1_c4nt_c4ptur3_fl4g5_unt17_1v3_h4d_a1l_my_0xCAFEBABE}`

## Overview

`coffee_invocation` is a PIE ELF that embeds two Java class files and drives them through JNI.

The native code:

1. creates a JVM
2. hooks `java/lang/Shutdown.halt0`
3. rewrites cached boxed values such as `Byte`, `Short`, `Character`, `Boolean`
4. runs `Verify1`
5. runs `Verify2`
6. if both wrappers return `0`, prints the supplied password as `HTB{<password>}`

So the solve is to recover the exact 52-character password accepted by both verifiers.

## Embedded Classes

The Java classes are stored raw in the ELF. Searching for `CAFEBABE` finds them:

```bash
grep -oba $'\xca\xfe\xba\xbe' coffee_invocation
```

Offsets:

- `0x5180` -> `Verify1`
- `0x5680` -> `Verify2`

## Verify1

The first wrapper:

- hooks `Shutdown.halt0` to store exit codes in a global instead of terminating
- remaps cached `Byte` objects using the table at virtual address `0x74c0`
- remaps cached `Short` objects using the table at virtual address `0x75e0`
- passes:
  - `password[:26]`
  - a fixed 26-byte target string from `0x7480`

The target string is:

```text
~PL{A;PL{?;:=|PIC{HzP:A;~x
```

`Verify1` checks:

```java
Byte.valueOf(source[i]) == Short.valueOf(target[i])
```

after the native cache remaps.

For this binary:

- the `Byte` table is a rotation by `0x51`
- the `Short` table is descending from `0x00, 0xff, 0xfe, ...`

Reversing the mapping gives the first half:

```text
1_c4nt_c4ptur3_fl4g5_unt17
```

## Verify2

The second wrapper:

- initializes the exit-code global to `2`
- hooks `Shutdown.halt0` again
- installs the first `Character` mapping from a table of 13 mappings
- swaps `Boolean.TRUE` and `Boolean.FALSE`
- passes `password[26:52]` into `Verify2`

The important detail is the exit hook:

- on `System.exit(3)`, it installs mapping 2
- on `System.exit(4)`, it installs mapping 3
- ...
- on `System.exit(15)`, it resets the global to `0`

So each successful 2-character block advances to the next character mapping. There are 13 blocks total.

### Actual Logic

Because `Boolean.TRUE` and `Boolean.FALSE` are swapped:

- `complexSort(inputPair, true)` does **not** sort the input pair
- `complexSort(constant, false)` **does** sort the full mapped constant

That means block `i` checks:

```text
mapped(input[2*i:2*i+2]) == sorted(mapped(full_constant))[2*i:2*i+2]
```

The full constant from `Verify2` is:

```text
Cr1KD5mk0_uUzQYifaGVqlN2B3wvpgPtSx6Odo{8hjJLHy9IXb4RnWZ}TAFEsMce7
```

Inverting the 13 installed character maps against those sorted slices yields the second half:

```text
_1v3_h4d_a1l_my_0xCAFEBABE
```

## Final Password

Concatenating both halves:

```text
1_c4nt_c4ptur3_fl4g5_unt17_1v3_h4d_a1l_my_0xCAFEBABE
```

The program prints the supplied password between `HTB{` and `}`, so the final flag is:

```text
HTB{1_c4nt_c4ptur3_fl4g5_unt17_1v3_h4d_a1l_my_0xCAFEBABE}
```

## Repro Script

```python
from pathlib import Path

b = Path("coffee_invocation").read_bytes()

# Verify1
byte_map = list(b[0x64c0:0x64c0 + 256])
short_map = list(b[0x65e0:0x65e0 + 256])
enc1 = b[0x6480:0x6480 + 26]

part1 = "".join(chr(byte_map.index(short_map[c])) for c in enc1)

# Verify2
const = "Cr1KD5mk0_uUzQYifaGVqlN2B3wvpgPtSx6Odo{8hjJLHy9IXb4RnWZ}TAFEsMce7"
maps = [
    list(b[0x6700 + i * 0x120:0x6700 + i * 0x120 + 127].decode("latin1"))
    for i in range(13)
]

part2_chars = []
for i, mp in enumerate(maps):
    mapped_const = "".join(mp[ord(c)] for c in const)
    sorted_full = "".join(sorted(mapped_const))
    pair = sorted_full[2 * i:2 * i + 2]
    part2_chars.append(chr(mp.index(pair[0])))
    part2_chars.append(chr(mp.index(pair[1])))

part2 = "".join(part2_chars)

print(f"HTB{{{part1}{part2}}}")
```
