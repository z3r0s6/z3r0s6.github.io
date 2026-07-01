---
title: "Reverse Engineering - Regas Town"
date: 2026-05-10
tags: ["HackTheBox", "Reverse Engineering"]
categories: ["Machines&Challenges"]
difficulty: "Medium"
os: "Linux"
author: "z3r0s"
---
# Rega's Town - HTB Reverse Engineering Challenge Writeup

## Challenge Info
- **Category:** Reverse Engineering
- **Description:** Welcome to Rega Town, a quaint little place where everyone communicates through the magic of patterns and rules!

## Analysis

The challenge provides a 64-bit ELF binary written in Rust. Running it prompts for a "secret passphrase" and validates it against a series of regex patterns.

```
$ ./rega_town
Welcome to our secret town!
Enter secret passphrase:
```

### Extracting the Regex Patterns

Using `strings` on the binary reveals all the regex patterns concatenated together:

```
^.{33}$
(?:^[\x48][\x54][\x42]).*
^.{3}(\x7b).*(\x7d)$
^[[:upper:]]{3}.[[:upper:]].{3}[[:upper:]].{3}[[:upper:]].{3}[[:upper:]].{4}[[:upper:]].{2}[[:upper:]].{3}[[:upper:]].{4}$
(?:.*\x5f.*)
(?:.[^0-9]*\d.*){5}
.{24}\x54.\x65.\x54.*
^.{4}[X-Z]\d._[A]\D\d.................[[:upper:]][n-x]{2}[n|c].$
.{11}_T[h|7]\d_[[:upper:]]\dn[a-h]_[O]\d_[[:alpha:]]{3}_.{5}
```

### Solving the Constraints

Each pattern constrains specific positions of the 33-character flag:

| Pattern | Constraint |
|---------|-----------|
| `^.{33}$` | Total length is exactly 33 characters |
| `(?:^[\x48][\x54][\x42]).*` | Starts with `HTB` (hex 48=H, 54=T, 42=B) |
| `^.{3}(\x7b).*(\x7d)$` | Position 3 is `{` (0x7b), last char is `}` (0x7d) |
| `^[[:upper:]]{3}.[[:upper:]]...` | Uppercase letters at positions 0,1,2,4,8,12,16,21,24,28 |
| `(?:.*\x5f.*)` | Contains underscores (0x5f = `_`) |
| `(?:.[^0-9]*\d.*){5}` | Contains at least 5 digits |
| `.{24}\x54.\x65.\x54.*` | Position 24=`T`, 26=`e`, 28=`T` |
| `^.{4}[X-Z]\d._[A]\D\d...[[:upper:]][n-x]{2}[n\|c].$` | pos4=[X-Z], pos5=digit, pos7=`_`, pos8=`A`, pos9=non-digit, pos10=digit, pos29-30=[n-x], pos31=[n,\|,c] |
| `.{11}_T[h\|7]\d_[[:upper:]]\dn[a-h]_[O]\d_[[:alpha:]]{3}_.{5}` | pos11=`_`, pos12=`T`, pos13=[h,7], pos14=digit, pos15=`_`, pos16=upper, pos17=digit, pos18=`n`, pos19=[a-h], pos20=`_`, pos21=`O`, pos22=digit, pos23=`_`, pos25=alpha, pos27=`_` |

### Building the Flag

Mapping all constraints to character positions:

```
Pos: 0  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15 16
Chr: H  T  B  {  Y  0  u  _  A  r  3  _  T  h  3  _  K

Pos: 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32
Chr: 1  n  g  _  O  7  _  T  h  e  _  T  o  w  n  }
```

This spells out the leet-speak phrase: **"You Are The King Of The Town"**

- `Y0u` = You
- `Ar3` = Are
- `Th3` = The
- `K1ng` = King
- `O7` = Of (leet-speak)
- `The` = The
- `Town` = Town

### Verification

```
$ echo "HTB{Y0u_Ar3_Th3_K1ng_O7_The_Town}" | ./rega_town
Welcome to our secret town!
Enter secret passphrase:
Correct one of us!!
```

## Flag

```
HTB{Y0u_Ar3_Th3_K1ng_O7_The_Town}
```
