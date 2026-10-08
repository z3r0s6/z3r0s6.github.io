---
title: "Reverse Engineering - Maze"
date: 2026-05-10
tags: ["HackTheBox", "Reverse Engineering"]
categories: ["Machines&Challenges"]
difficulty: "Medium"
os: "Windows"
author: "z3r0s"
---
# HTB Reverse Challenge: Maze

## Challenge Overview

**Category:** Reverse Engineering  
**Difficulty:** Medium  
**Flag:** `HTB{w0W_Y0u_C0uld_E5c4p3_Th1s_M4Z33!!}`

We are given a Windows executable (`maze.exe`), an encrypted zip (`enc_maze.zip`), and an image (`maze.png`). The goal is to navigate through multiple layers of obfuscation to find the flag.

---

## Solution

### Step 1: Identify and Unpack PyInstaller

```bash
$ file maze.exe
maze.exe: PE32+ executable for MS Windows, x86-64
$ strings maze.exe | grep PyInstaller
PyInstaller: pyi_win32_utils_to_utf8 failed.
```

The binary is a PyInstaller-packed Python 3.8 application. We extract it using `pyinstxtractor`:

```bash
$ python3 pyinstxtractor.py maze.exe
[+] Python version: 3.8
[+] Possible entry point: maze.pyc
```

### Step 2: Decompile the Main Script

Using `uncompyle6` on `maze.pyc`, we recover the main logic:

```python
import sys, obf_path

ZIPFILE = "enc_maze.zip"
inp = input("Now There are two paths from here. Which path will u choose? => ")

if inp == "Y0u_St1ll_1N_4_M4z3":
    obf_path.obfuscate_route()
else:
    print("Unfortunately, this path leads to a dead end.")
    sys.exit(0)

import pyzipper

def decrypt(file_path, word):
    with pyzipper.AESZipFile(file_path, "r", compression=pyzipper.ZIP_LZMA,
                             encryption=pyzipper.WZ_AES) as extracted_zip:
        extracted_zip.extractall(pwd=word)

decrypt(ZIPFILE, "Y0u_Ar3_W4lkiNG_t0_Y0uR_D34TH".encode())

with open("maze", "rb") as file:
    content = file.read()
data = bytearray(content)
data = [x for x in data]
key = [0] * len(data)

for i in range(0, len(data), 10):
    data[i] = (data[i] + 80) % 256

for i in range(0, len(data), 10):
    data[i] = (data[i] ^ key[i % len(key)]) % 256

with open("dec_maze", "wb") as f:
    for b in data:
        f.write(bytes([b]))
```

Key findings:
- The zip password is `Y0u_Ar3_W4lkiNG_t0_Y0uR_D34TH`
- The decryption modifies every 10th byte by adding 80
- The XOR key is all zeros (a red herring) -- the real key comes from `obf_path`

### Step 3: Deobfuscate `obf_path`

The `obf_path` module is inside the PYZ archive. After extracting and decompiling, we find it uses multiple layers of compression (lzma + zlib) and obfuscation (`__regboss__` variable spam).

After peeling all layers, the core logic reads specific bytes from `maze.png` to compute a random seed:

```python
index = open("maze.png", "rb").read()
seed = index[4817] + index[2624] + index[2640] + index[2720]
# seed = 221 + 96 + 53 + 123 = 493
```

It then hints at generating a key:
```
seed(493)
for i in range(300):
    randint(32, 125)
```

### Step 4: Decrypt the ELF Binary

Using the correct random key instead of the all-zeros key:

```python
from random import seed, randint
import pyzipper

# Extract the encrypted zip
with pyzipper.AESZipFile("enc_maze.zip", "r", compression=pyzipper.ZIP_LZMA,
                         encryption=pyzipper.WZ_AES) as z:
    z.extractall(pwd=b"Y0u_Ar3_W4lkiNG_t0_Y0uR_D34TH")

# Generate the real key
seed(493)
key = [randint(32, 125) for _ in range(300)]

# Read and transform
with open("maze", "rb") as f:
    data = bytearray(f.read())

for i in range(0, len(data), 10):
    data[i] = (data[i] + 80) % 256
for i in range(0, len(data), 10):
    data[i] = (data[i] ^ key[i % len(key)]) % 256

with open("dec_maze", "wb") as f:
    f.write(data)
```

This produces a valid ELF 64-bit binary.

### Step 5: Reverse the ELF Binary

Disassembling `dec_maze` reveals the flag validation logic:

1. Read input via `fgets`
2. Check that the first 3 characters are `H`, `T`, `B`
3. For each position `i` (from 1 to len-2), verify:
   ```
   input[i-1] + input[i] + input[i+1] == expected_sum[i-1]
   ```
4. The expected sums are stored in `.rodata` at offset `0x2060`

The expected sums array:
```
[222, 273, 308, 290, 254, 230, 271, 232, 254, 260, 279, 210, 232, 273,
 325, 303, 264, 217, 221, 204, 263, 215, 258, 230, 283, 237, 268, 259,
 287, 224, 219, 193, 192, 135, 117, 191]
```

### Step 6: Solve for the Flag

Since we know the first 3 characters (`HTB`) and each sum constrains a sliding window of 3 characters, we can derive each subsequent character:

```
flag[i+2] = sums[i] - flag[i] - flag[i+1]
```

Starting from `H=72, T=84, B=66`:
- `sums[1] = T + B + flag[3]` => `flag[3] = 273 - 84 - 66 = 123 = '{'`
- `sums[2] = B + { + flag[4]` => `flag[4] = 308 - 66 - 123 = 119 = 'w'`
- ... and so on for the entire flag.

## Flag

```
HTB{w0W_Y0u_C0uld_E5c4p3_Th1s_M4Z33!!}
```
