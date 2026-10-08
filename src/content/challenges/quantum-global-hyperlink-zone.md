---
title: "Quantum - global hyperlink zone"
date: 2026-05-10
tags: ["HackTheBox", "Quantum"]
categories: ["Machines&Challenges"]
author: "z3r0s"
---
# HTB Write-up: Global Hyperlink Zone

Link - https://app.hackthebox.com/challenges/Global%2520Hyperlink%2520Zone



---


**Category:** Quantum
**Difficulty:** Very Easy

### Summary

The challenge provides a Python script for a server that expects a specific sequence of quantum gates. The goal is to build a quantum circuit that satisfies a set of conditions defined in a validation function within the script. The solution involves creating a specific entangled state across five qubits.

---

### Recon (Analyzing the code)

After downloading the file, `server.py`, it's immediately clear how to solve this. The whole logic is in the `validate` function:

```python
def validate(shares):
    # 1 - No uniformity
    if any(set(share) in ({0}, {255}) for share in shares):
        return False

    # 2 - Correlation and anti-correlation
    if (
        shares[0] == shares[1] and
        shares[1] == shares[3] and
        shares[2] == shares[4] and
        shares[4] != shares[0]
    ):
        return True

    return False
```

Here, `shares` is a list of 5 byte arrays. `shares[0]` contains the 256 measurement outcomes for qubit 0, `shares[1]` for qubit 1, and so on.

**Breaking down the logic:**

1.  **`if any(set(share) in ({0}, {255}) for share in shares): return False`**
    *   This checks if any qubit always measured `0` (byte `0`) or always measured `1` (byte `255`). This is forbidden.
    *   **In simple terms:** Every qubit needs to be in a superposition. The easiest way to achieve this is with a Hadamard (H) gate.

2.  **`shares[0] == shares[1] and shares[1] == shares[3]`**
    *   The measurement outcomes for qubits 0, 1, and 3 must be **identical** across all 256 shots.
    *   **How to achieve this:** They must be entangled. If qubit 0 is measured as 0, qubits 1 and 3 must also be 0. This is a classic Greenbergerâ€“Horneâ€“Zeilinger (GHZ) state.

3.  **`shares[2] == shares[4]`**
    *   Measurement outcomes for qubits 2 and 4 must also be **identical**.
    *   **How to achieve this:** Entangle them to create a Bell state.

4.  **`shares[4] != shares[0]`**
    *   The results for the (2, 4) group must be the **opposite** of the (0, 1, 3) group.
    *   **How to achieve this:** The two groups must be anti-correlated. If qubit 0 is 0, qubit 4 must be 1.

---

### Strategy

Based on the analysis, the plan is straightforward:

1.  **Pick a "control" qubit.** Let's use qubit 0.
2.  **Create superposition (Condition 1).** Apply a Hadamard gate to the control qubit.
    *   `H:0`
3.  **Make qubits 1 and 3 identical to qubit 0 (Condition 2).** Use CNOT (CX) gates with qubit 0 as the control.
    *   `CX:0,1`
    *   `CX:0,3`
4.  **Make qubits 2 and 4 the opposite of qubit 0 (Conditions 3 & 4).**
    *   First, entangle them with qubit 0 so they follow it:
        *   `CX:0,2`
        *   `CX:0,4`
    *   Now all 5 qubits are correlated. To make the (2, 4) group opposite, just flip their states with a Pauli-X (NOT) gate.
        *   `X:2`
        *   `X:4`

---

### Solution

Combining all steps into a single, semicolon-separated string gives us the final payload:

```
H:0;CX:0,1;CX:0,3;CX:0,2;CX:0,4;X:2;X:4
```

This sequence creates a superposition of two states: `|00101>` and `|11010>`, which perfectly satisfies all the conditions.

---

### Execution

All that's left is to connect via `nc` and send the string.

```
â”Œâ”€â”€(userã‰¿hostname)-[~]
â””â”€$ nc 1.1.1.1 0000

                 _             _       _      _
                /\ \          / /\    / /\  /\ \
               /  \ \        / / /   / / / /  \ \
              / /\ \_\      / /_/   / / /_/ /\ \ \
             / / /\/_/     / /\ \__/ / /___/ /\ \ \
            / / / ______  / /\ \___\/ /\___\/ / / /
           / / / /\_____\/ / /\/___/ /       / / /
          / / /  \/____ / / /   / / /       / / /    _
         / / /_____/ / / / /   / / /        \ \ \__/\_\
        / / /______\/ / / /   / / /          \ \___\/ /
        \/___________/\/_/    \/_/            \/___/_/


Welcome to the Global Hyperlink Zone! The first quantum internet prototype by Qubitrix.
Please send the instructions to initialize the hyperlink.
Specify the instructions : H:0;CX:0,1;CX:0,3;CX:0,2;CX:0,4;X:2;X:4
Hyperlink initialized successfully! Connection ID: HTB{...flag...}
```

And that's the challenge solved.

