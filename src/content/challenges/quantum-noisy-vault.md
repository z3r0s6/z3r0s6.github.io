---
title: "Quantum - noisy vault"
date: 2026-05-10
tags: ["HackTheBox", "Quantum"]
categories: ["Machines&Challenges"]
author: "z3r0s"
---
# Noisy Vault Writeup

## Summary

The challenge description mentions a 13-qubit system and a 9-bit key, but the actual service uses:

- `64` data qubits
- `16` ancilla qubits
- a single oracle query
- `4096` noisy measurement shots

The goal is to recover the hidden 64-bit `secret_key` and submit it in one unlock attempt.

## Root Cause

The service prepares the secret as a computational basis state by applying `X` on each data qubit whose key bit is `1`.

That means the hidden state is not a superposition. It is just a classical bitstring encoded into qubits.

The oracle then:

1. applies our circuit
2. injects several idle noise cycles
3. measures only the 64 data qubits
4. returns the shot histogram

Because the state starts as a basis state, the best strategy is not error correction. It is to avoid disturbing the data while still passing the validator.

## Validator Bypass

The validator rejects circuits unless both of these are true after transpilation:

- at least `16` data/ancilla links
- at least `4` active ancillas

Ancillas start in `|0>`. A `CZ` gate with a target ancilla still in `|0>` is logically inert, so it satisfies the structural checks without changing the stored key.

The minimal valid circuit is:

```text
CZ:0,64;CZ:1,65;CZ:2,66;CZ:3,67;CZ:4,68;CZ:5,69;CZ:6,70;CZ:7,71;CZ:8,72;CZ:9,73;CZ:10,74;CZ:11,75;CZ:12,76;CZ:13,77;CZ:14,78;CZ:15,79
```

This creates 16 data/ancilla links and touches 16 ancillas, so it passes validation while adding only the unavoidable gate noise.

## Recovering the Key

The oracle returns a noisy distribution of 64-bit measurement strings. Since the hidden state is classical and the corrective circuit is effectively a no-op, the most frequent bitstring is the true secret.

One detail matters: Qiskit prints measurement keys in reversed classical-bit order relative to the original qubit indices, so the recovered oracle winner must be reversed before submitting.

Recovery rule:

1. send the inert `CZ` circuit
2. parse the returned JSON histogram
3. take the state with the highest count
4. reverse the string
5. submit it as the vault code

## Solve Script

I added a small helper here:

- [live_writer.py](/home/kali/Downloads/quantum_noisy_vault/live_writer.py)

It sends the oracle request, waits until the transcript contains the result JSON, extracts the highest-frequency state, reverses it, and submits the final code.

Example usage:

```bash
python3 /home/kali/Downloads/quantum_noisy_vault/live_writer.py /tmp/noisy_live_run.txt | nc -nv 154.57.164.81 32489 | tee /tmp/noisy_live_run.txt
```

## Flag

```text
HTB{Qu4nTUm_n01s3_c4nt_st0p_th3_v4ult_h4ck!}
```
