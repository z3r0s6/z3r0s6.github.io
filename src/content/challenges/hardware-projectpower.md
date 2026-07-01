---
title: "Hardware - ProjectPower"
date: 2026-05-10
tags: ["HackTheBox", "Hardware"]
categories: ["Machines&Challenges"]
author: "z3r0s"
---
# Project Power Writeup

## Summary

The challenge exposes a remote interface to an embedded device performing AES-128 encryption. The interface lets us:

- send a chosen 16-byte plaintext and receive a corresponding power trace
- submit a candidate AES key and receive the flag if the key is correct

This is a standard side-channel setup. A simple Correlation Power Analysis (CPA) attack against the first AES round is enough to recover the key.

## Files Used

- `socket_interface.py`
- `remote_lab_layout.png`

`file.zip` was intentionally ignored per the updated instruction.

## Protocol Notes

`socket_interface.py` shows two menu options on the remote socket:

- option `1`: send a raw 16-byte plaintext, receive a base64-encoded NumPy trace
- option `2`: send a 32-character hex AES key, receive an ASCII response

The helper function:

```python
def b64_decode_trace(leakage):
    byte_data = base64.b64decode(leakage)
    return np.frombuffer(byte_data)
```

indicates that the returned trace is raw binary for a NumPy array, which defaults to `float64` when decoded with `np.frombuffer(...)`.

The lab diagram confirms the intended side-channel path:

- chosen plaintext reaches the target
- the target encrypts it with AES-128
- power consumption is captured and returned to us

## Attack

I wrote `solve.py` to automate collection and analysis.

### Leakage Model

For each AES key byte guess `k`, CPA models the first-round SubBytes output:

```text
HW(SBOX[plaintext_byte XOR k])
```

where `HW` is Hamming weight.

### Correlation

For each byte position:

1. collect traces for random 16-byte plaintexts
2. compute the hypothetical Hamming-weight leakage for all 256 key guesses
3. correlate each guess against every sample point in the measured traces
4. select the key byte with the highest absolute correlation

The leakage was very strong. Only 30 traces were sufficient.

## Reproduction

Run:

```bash
python3 solve.py --traces 30 --save traces30.npz
```

The solver:

- collects traces from `154.57.164.83:32534`
- runs CPA for all 16 AES bytes
- submits the recovered key with menu option `2`

## Results

Recovered AES-128 key:

```text
35425203F4BF23C7F93444BF772F2E1F
```

Flag:

```text
HTB{51d3_ch4nn31_c4n_8234k_3v3n_7h3_m057_53cu23_d3v1c35!@^5%2}
```

## Notes

This challenge is a textbook CPA break of AES on a leaky embedded implementation. Because the traces are already aligned and low-noise, no advanced preprocessing was required.
