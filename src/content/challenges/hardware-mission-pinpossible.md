---
title: "Hardware - mission pinpossible"
date: 2026-05-10
tags: ["HackTheBox", "Hardware"]
categories: ["Machines&Challenges"]
author: "z3r0s"
---
# Mission Pinpossible Writeup

## Files

- `op_pinpossible.logicdata`
- `security_keypad.jpeg`

## Goal

Recover the password shown on the keypad LCD from the intercepted monitor traffic.

## 1. Identify the bus

The photo shows a standard 16x2 HD44780 LCD connected through a common I2C backpack based on a `PCF8574`.

That matters because:

- the backpack only needs `SDA` and `SCL`
- the logic capture contains exactly two digital channels
- the I2C slave address used by these backpacks is commonly `0x27`/`0x3f` depending on wiring

In this capture, the observed write address is `0x4e`, which is the 8-bit write form of `0x27`.

## 2. Open the legacy Saleae capture

`.logicdata` is a Saleae Logic 1.x capture, so it cannot be opened directly by Logic 2.

I used the legacy Logic 1.x app to load the capture and export the two channels to VCD, then decoded the resulting waveform.

From the exported signal:

- `Channel 0` = `SDA`
- `Channel 1` = `SCL`

## 3. Decode I2C

After grouping same-timestamp transitions correctly, the bus decodes cleanly as repeated 2-byte I2C writes:

- byte 1: `0x4e` (LCD backpack write address)
- byte 2: one `PCF8574` port-state byte

Example beginning of the trace:

```text
0x4e 0x08
0x4e 0x0c
0x4e 0x08
0x4e 0x18
0x4e 0x1c
0x4e 0x18
```

This matches the usual HD44780 4-bit interface over `PCF8574`:

- upper nibble = LCD data nibble
- bit 2 = `EN`
- bit 0 = `RS`
- bit 3 = backlight

So the byte pair above is:

- latch high nibble `0x0`
- latch low nibble `0x1`

which reconstructs LCD command `0x01` (`clear display`).

## 4. Rebuild LCD bytes

Using each falling edge of `EN` as a nibble latch point and pairing nibbles back into bytes gives LCD operations like:

```text
CMD  0x01
CMD  0x80
DATA 0x20  ' '
DATA 0x45  'E'
DATA 0x6e  'n'
DATA 0x74  't'
DATA 0x65  'e'
DATA 0x72  'r'
...
CMD  0xc0
DATA 0x48  'H'
```

The firmware repeatedly redraws:

- line 1: ` Enter Password `
- line 2: masked password, with the most recently typed character briefly visible

## 5. Recover the password

Watching the visible character that appears at the end of the masked line on each refresh yields:

```text
H
T
B
{
8
4
d
_
d
3
5
1
9
n
_
c
```

That only gives the first visible 16 characters:

```text
HTB{84d_d3519n_c
```

At first glance that looks like the whole password, but this LCD controller keeps a wider hidden line buffer in DDRAM than the 16 columns physically shown on screen.

For a 16x2 HD44780 display:

- visible line 2 columns map to DDRAM `0x40-0x4f`
- hidden continuation of that same row keeps going at `0x50+`

So after the 16th visible password character, the firmware keeps writing more characters off-screen.

Extracting the last non-`*` value written to each sequential line-2 DDRAM address gives:

```text
0x40 H
0x41 T
0x42 B
0x43 {
0x44 8
0x45 4
0x46 d
0x47 _
0x48 d
0x49 3
0x4a 5
0x4b 1
0x4c 9
0x4d n
0x4e _
0x4f c
0x50 4
0x51 n
0x52 _
0x53 1
0x54 3
0x55 4
0x56 d
0x57 _
0x58 7
0x59 0
0x5a _
0x5b 1
0x5c 3
0x5d 4
0x5e k
0x5f 5
0x60 !
0x61 d
0x62 @
0x63 }
```

Combined:

```text
HTB{84d_d3519n_c4n_134d_70_134k5!d@}
```

The next byte written is `0x00`, so the string terminates there.

## Flag

```text
HTB{84d_d3519n_c4n_134d_70_134k5!d@}
```
