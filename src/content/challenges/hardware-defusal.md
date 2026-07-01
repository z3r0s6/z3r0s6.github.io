---
title: "Hardware - defusal"
date: 2026-05-10
tags: ["HackTheBox", "Hardware"]
categories: ["Machines&Challenges"]
author: "z3r0s"
---
# Hardware Defusal Writeup

## Files

Ignoring `file.zip` as requested, the challenge files are:

- `Defusal`
- `circuit.png`
- `C4-BOMB.mp4`

## 1. Triage

`Defusal` is an AVR firmware ELF:

```text
ELF 32-bit LSB executable, Atmel AVR 8-bit, statically linked, with debug_info, not stripped
```

That makes this mostly a firmware reverse-engineering problem.

## 2. Key Firmware Findings

Useful strings inside the binary:

- `123A456B789C*0#D`
- `C4 Explosive v.1`
- `Enter Password:`
- ` Bomb has been`
- `    DEFUSED!`
- ` BOOOOOOOOOOOM!`
- `735560`
- `7355608`

The important globals are:

- `inputPassword` at `0x8003c0`
- `correctPassword` at `0x8003ba`
- `print_flag()` at `0x00000abc`

`correctPassword` is not a raw char array. It is an Arduino `String` object. The constructor code initializes it from the bytes at `0x8003b1`, which are:

```text
7355608
```

So the real password is:

```text
7355608
```

## 3. Main Logic

In `main`, keypad input is appended to `inputPassword`.

When `#` is pressed, the firmware compares `inputPassword` to `correctPassword` as `String`s.

- If they match, it calls `print_flag()`
- If they do not match, it shows the boom message

So the defusal code is definitely `7355608`.

## 4. Decoding `print_flag()`

`print_flag()` allocates a local variable named `flag` with DWARF type:

```text
byte flag[37][8]
```

The important correction is that this table is copied from AVR SRAM address `0x021e`, which comes from the initialized `.data` section, not from `.text`.

For each of the 37 glyphs, the function XORs each row with the matching byte from `correctPassword`:

```c
xorValue = flag[x][dot] ^ correctPassword[dot];
```

Then it sends the result to the LED matrix row-by-row.

Using the real table from `.data[0x021e ... 0x021e+0x128)` and XORing with `7355608` produces 37 8x8 glyphs. The ambiguous symbols are leetspeak digits, not letters:

- `1` instead of `I`
- `4` instead of `A`
- `0` instead of `O`

Reading the glyphs in order gives:

```text
H T B { B 1 N G O _ B 4 N G O _ B 0 N G O _ B 1 S H _ B 4 S H _ B 0 S H }
```

## Flag

```text
HTB{B1NGO_B4NGO_B0NGO_B1SH_B4SH_B0SH}
```

## Notes

- `circuit.png` is still useful because it confirms the keypad and matrix hardware layout.
- `C4-BOMB.mp4` is just a rotating render of the device and is not needed to recover the flag.
