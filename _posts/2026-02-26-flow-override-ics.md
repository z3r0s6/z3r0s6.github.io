---
title: "Flow Override - ICS Challenge"
date: 2026-02-26 00:02:00 +0000
categories: [HTB-Challenges]
tags: [ics, s7comm, siemens, plc, water-treatment]
---

## Challenge Overview

The **Flow Override** challenge simulates a compromised water treatment plant network running Siemens PLCs with S7comm protocol. The objective requires attackers to disrupt at least three pieces of equipment and retrieve a flag through direct PLC memory manipulation.

## Technical Foundation

### S7 Communication Protocol

The exploit leverages the proprietary **S7comm protocol** used by Siemens S7 PLCs. The Python library `python-snap7` provides the interface for memory access, utilizing `snap7.client.Client` objects and utility functions like `set_bool` and `get_bool` for boolean data manipulation within PLC buffers.

### PLC Memory Architecture

Siemens PLCs organize data in **Data Blocks (DBs)**. Memory addressing follows the format `DBX.Y.Z` where:

- **X** = Data Block number
- **Y** = Byte offset
- **Z** = Bit offset within the byte

The exploit targets **Data Block 1 (DB1)**, with the flag ultimately located at `DB1.48.5`.

## Exploit Strategy

### Phase 1: Pre-Condition Establishment

The script awaits activation of the `heatexch_cold_side_valve`, suggesting this represents a necessary system state for flag activation.

### Phase 2: Equipment Disruption

The exploit disables three critical pieces of equipment by manipulating control bits:

| Equipment | Address | Action | Effect |
|-----------|---------|--------|--------|
| Water Tank Input | `DB1.1.1` | Enable | Continuous inflow |
| Water Tank Output | `DB1.1.0` | Disable | Blocked outflow |
| Chlorine Tank Input | `DB1.10.0` | Enable | Continuous inflow |
| Chlorine Tank Output | `DB1.10.1` | Disable | Blocked outflow |

The `preset_exact_values()` function sets `DB1.4.0` to `True`, enabling manual override mode. This prevents the standard PLC program from interfering with valve control, forcing both tanks into simultaneous overflow.

### Phase 3: Flag Retrieval

The `scan_for_flag()` function performs targeted bit-flipping across byte 48. For each candidate bit:

1. Read current state
2. Write inverted value
3. Query status API for flag presence
4. Restore original value if flag not found

The script successfully identifies **`DB1.48.5`** as the flag-triggering bit.

## Critical Code Pattern

```python
orig = get_bool(db, byte, bit)
write_bit(plc, db, byte, bit, not orig)
# Check for success
write_bit(plc, db, byte, bit, orig)  # Restore if no flag
```

This ensures the critical overflow condition persists across all flag-checking iterations.

## Key Findings

- Direct memory access via S7comm enabled complete control bypass
- Manual mode activation (`DB1.4.0`) prevented PLC firmware countermeasures
- Simultaneous tank overflow created conditions for flag activation
- Brute-force bit-scanning across a narrow range proved efficient
