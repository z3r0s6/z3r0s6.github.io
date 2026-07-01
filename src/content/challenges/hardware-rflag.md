---
title: "Hardware - rflag"
date: 2026-05-10
tags: ["HackTheBox", "Hardware"]
categories: ["Machines&Challenges"]
author: "z3r0s"
---
# hardware_rflag Writeup

## Flag

`HTB{RF_H4ck1n6_1s_c00l!!!}`

## Approach

The archive only contains one useful file: `signal.cf32`, a raw complex64 IQ capture.

I loaded the samples with NumPy and inspected the amplitude envelope:

- The capture has `476160` complex samples.
- Thresholding the magnitude shows runs quantized almost perfectly at `~899` samples and `~1798` samples.
- The first part of the signal is a preamble, followed by data encoded as alternating `01` / `10` unit pairs.

That pattern is consistent with Manchester-style encoding.

## Decode

1. Read `signal.cf32` as `np.complex64`.
2. Compute the envelope with `np.abs(...)`.
3. Smooth slightly and threshold around `0.7` to recover OOK high/low states.
4. Convert run lengths into unit slots using the base pulse width `899`.
5. Skip the first `8` low preamble units.
6. Group the remaining unit stream into 2-bit symbols:
   - `01 -> 0`
   - `10 -> 1`
7. Pack the resulting bits into bytes.

That yields:

```text
aa aa aa aa 0c 4e 48 54 42 7b 52 46 5f 48 34 63 6b 31 6e 36 5f 31 73 5f 63 30 30 6c 21 21 21 7d
```

ASCII from the `48 54 42 7b ...` section is:

```text
HTB{RF_H4ck1n6_1s_c00l!!!}
```

## Repro Script

```python
import numpy as np

x = np.fromfile("signal.cf32", dtype=np.complex64)
a = np.abs(x)
s = np.convolve(a, np.ones(8) / 8, mode="same")
m = s > 0.7

runs = []
start = 0
cur = m[0]
for i, v in enumerate(m[1:], 1):
    if v != cur:
        runs.append((int(cur), round((i - start) / 899)))
        start = i
        cur = v
runs.append((int(cur), round((len(m) - start) / 899)))

units = "".join(str(level) * n for level, n in runs)
start = 8

pairs = [
    units[i:i + 2]
    for i in range(start, len(units) - ((len(units) - start) % 2), 2)
]

bits = "".join("0" if p == "01" else "1" if p == "10" else "" for p in pairs)
bits = bits[:len(bits) // 8 * 8]
data = bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))

print(data)
print(data[data.find(b"HTB{"):].decode())
```

Expected output:

```text
b'\xaa\xaa\xaa\xaa\x0cNHTB{RF_H4ck1n6_1s_c00l!!!}'
HTB{RF_H4ck1n6_1s_c00l!!!}
```
