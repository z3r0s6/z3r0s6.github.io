---
title: "Hardware - Espresso"
date: 2026-06-05
tags: ["HackTheBox", "Hardware", "VeryEasy"]
categories: ["Machines&Challenges"]
difficulty: "Very Easy"
author: "z3r0s"
---

# Hack The Box Challenge Writeup: Espresso

## Challenge

Name: Espresso

Scenario:

> Someone leaked the new Espresso firmware, can you try to figure out what it does?


## Summary

The challenge provides an ESP32 firmware image. The firmware checks whether it is running on expected hardware by comparing the ESP32 factory MAC address against zero bytes. If the check fails, it prints anti-clone messages. If the check passes, it generates the flag by XOR decoding a 31 byte table stored in the firmware data segment.

The decoded flag is:

```text
HTB{3mul4ting_hw_is_s0_c00l!!!}
```

## Files

After extracting the archive, the contents were:

```text
hw_espresso/
└── firmware.bin
```

The firmware image is 4 MiB:

```text
firmware.bin: data
```

Running `binwalk` identified an ESP32 flash layout:

```text
DECIMAL       HEXADECIMAL     DESCRIPTION
4096          0x1000          ESP Image (ESP32), bootloader
32768         0x8000          ESP32 Partition Table Entry: nvs
32800         0x8020          ESP32 Partition Table Entry: phy_init
32832         0x8040          ESP32 Partition Table Entry: factory, offset 0x10000, size 0x100000
65536         0x10000         ESP Image (ESP32), application
```

The application partition starts at flash offset `0x10000` and has size `0x100000`.

## Extracting The Application

The factory application partition can be carved out with:

```bash
dd if=hw_espresso/firmware.bin of=app_factory.bin bs=1 skip=65536 count=1048576 status=none
```

Running strings on the carved application showed the project name and useful challenge strings:

```text
espresso
flag did not generate correctly.
It seems you are running the firmware on cloned hadware.
Buy the real hardware, or perhaps try to emulate it. ;)
get_efuse_factory_mac
```

These strings show that the firmware performs a hardware check and that the flag is generated at runtime.

## ESP32 Image Layout

The ESP32 application image begins with an ESP image header. Parsing the segment table gives these load segments:

```text
0  vaddr 0x3f400020  size 0x8b68   flags R
1  vaddr 0x3ffb0000  size 0x2a6c   flags RW
2  vaddr 0x40080000  size 0x4a14   flags RX
3  vaddr 0x400d0020  size 0xc7b8   flags RX
4  vaddr 0x40084a14  size 0x60f4   flags RX
5  vaddr 0x50000000  size 0x28     flags RW
```

The important data segment starts at virtual address `0x3f400020`. Because the segment starts at file offset `0x20` inside `app_factory.bin`, a virtual address in that segment can be converted to a file offset like this:

```text
file_offset = virtual_address - 0x3f400020 + 0x20
```

For example:

```text
0x3f407688 - 0x3f400020 + 0x20 = 0x7688
```

## Reconstructing An ELF For Ghidra

To make analysis easier, I converted the ESP32 image segments into a minimal ELF file using the real load addresses. This allowed Ghidra to analyze cross-references correctly with the Xtensa processor module.

The application entry point is:

```text
0x400814ac
```

After importing the reconstructed ELF into Ghidra as `Xtensa:LE:32:default`, the key function was found at `0x400d5c34`.

## Main Challenge Logic

Ghidra decompiled the main challenge routine like this:

```c
void FUN_400d5c34(void)
{
  int iVar1;
  undefined4 uVar2;
  char local_40 [64];

  iVar1 = FUN_400d5c04();
  if (iVar1 == 0) {
    uVar2 = FUN_40088f4c();
    FUN_40088e74(1, tag, error_fmt, uVar2, tag,
                 "It seems you are running the firmware on cloned hadware.");
    uVar2 = FUN_40088f4c();
    FUN_40088e74(1, tag, error_fmt, uVar2, tag,
                 "Buy the real hardware, or perhaps try to emulate it. ;)");
  }
  else {
    FUN_400d5cb0(local_40, 0x20);
    if (local_40[0] == '\0') {
      uVar2 = FUN_40088f4c();
      FUN_40088e74(3, tag, info_fmt, uVar2, tag,
                   "flag did not generate correctly.");
    }
    else {
      uVar2 = FUN_40088f4c();
      FUN_40088e74(3, tag, info_fmt, uVar2, tag, local_40);
    }
  }
}
```

The function first calls `FUN_400d5c04()`. If that returns false, the firmware prints the anti-clone messages. If it returns true, it calls `FUN_400d5cb0()` to generate the flag into a local buffer.

## Hardware Check

The hardware check function decompiled to:

```c
bool FUN_400d5c04(void)
{
  int iVar1;
  undefined1 auStack_30 [6];
  undefined1 auStack_2a [42];

  memset(auStack_2a, 0, 6);
  FUN_400d78b0(auStack_30, 0);
  iVar1 = memcmp(auStack_30, auStack_2a, 6);
  return iVar1 == 0;
}
```

This checks whether the ESP32 factory MAC address is all zero bytes. On real hardware, this is not normally true, so the firmware reports cloned hardware. In an emulator, if the MAC is zeroed or the check is bypassed, the firmware proceeds to flag generation.

## Flag Generation

The flag generator was the important function:

```c
void FUN_400d5cb0(int param_1, uint param_2)
{
  uint i;

  if (0x1f < param_2) {
    for (i = 0; i < 0x1f; i = i + 1) {
      *(byte *)(param_1 + i) = PTR_DAT_400d07d8[i] ^ 0x42;
    }
    *(undefined1 *)(param_1 + 0x1f) = 0;
  }
}
```

This is a simple XOR decoder:

1. Check that the output buffer is larger than 31 bytes.
2. Read 31 encoded bytes from `PTR_DAT_400d07d8`.
3. XOR each byte with `0x42`.
4. Null terminate the result.

The pointer at `0x400d07d8` points to:

```text
0x3f407688
```

Converting that virtual address to a file offset gives:

```text
0x7688
```

The encoded bytes at that offset are:

```text
0a160039712f372e76362b2c251d2a351d2b311d31721d2172722e6363633f
```

XORing those bytes with `0x42` gives the flag.

## Python Decode Script

The following Python script extracts and decodes the flag directly from `app_factory.bin`:

```python
#!/usr/bin/env python3
from pathlib import Path


APP_PATH = Path("app_factory.bin")

# DROM segment from the ESP32 image:
#   file offset: 0x20
#   virtual address: 0x3f400020
#
# The encoded flag table is referenced by the firmware at virtual address
# 0x3f407688.
DROM_FILE_OFFSET = 0x20
DROM_VADDR = 0x3F400020
ENCODED_FLAG_VADDR = 0x3F407688
FLAG_LEN = 0x1F
XOR_KEY = 0x42


def vaddr_to_file_offset(vaddr: int) -> int:
    return vaddr - DROM_VADDR + DROM_FILE_OFFSET


def main() -> None:
    data = APP_PATH.read_bytes()
    encoded_offset = vaddr_to_file_offset(ENCODED_FLAG_VADDR)
    encoded = data[encoded_offset:encoded_offset + FLAG_LEN]
    decoded = bytes(byte ^ XOR_KEY for byte in encoded)

    print(f"encoded offset: 0x{encoded_offset:x}")
    print(f"encoded bytes:  {encoded.hex()}")
    print(f"flag:           {decoded.decode()}")


if __name__ == "__main__":
    main()
```

Running it:

```bash
python3 solve.py
```

Output:

```text
encoded offset: 0x7688
encoded bytes:  0a160039712f372e76362b2c251d2a351d2b311d31721d2172722e6363633f
flag:           HTB{3mul4ting_hw_is_s0_c00l!!!}
```

## Final Flag

```text
HTB{3mul4ting_hw_is_s0_c00l!!!}
```
